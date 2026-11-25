//! 서비스 본체: 스케줄러 틱 → 작업 큐 → 엔진 실행 → 프로파일 상태 갱신 → 이벤트 푸시.
//! 시각을 인자로 받아 서비스 루프와 시험이 같은 코드를 쓴다.
mod ipc_handler;
mod jobs_backup;
mod jobs_image;
mod jobs_maint;
mod restore;
#[cfg(test)]
mod tests;

pub use ipc_handler::IpcHandler;

use chrono::{DateTime, Local};
use kova_core::config::{ConfigStore, Profile, Settings};
use kova_core::jobs::{Enqueue, Job, JobQueue, Kind};
use kova_core::schedule::{should_run, should_run_maintenance, MAX_AUTO_RETRIES};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const REPO_LOCK_WAIT: Duration = Duration::from_secs(3);
/// 저장소 잠금 충돌(Busy) 메시지의 공통 머리말. 이 결과는 알림·웹훅을 보내지 않는다.
pub(crate) const BUSY_PREFIX: &str = "다른 작업이 저장소를 사용 중";
/// 잠금 충돌 뒤 이 시간 동안은 정기 스케줄이 같은 프로파일을 다시 큐에 넣지 않는다(30초마다 재큐 방지).
pub(crate) const LOCK_BUSY_COOLDOWN_SEC: f64 = 300.0;
/// 정기 유지보수(Verify/Gc)가 실패했을 때 다시 큐에 넣기 전 기다리는 시간(30초마다 무한 재큐 방지).
pub(crate) const MAINT_FAIL_COOLDOWN: Duration = Duration::from_secs(1800);
/// 구독자 한 명이 쌓아 둘 수 있는 이벤트 수. 넘치면(읽지 않는 구독자) 그 구독을 끊는다.
pub(crate) const SUB_CAPACITY: usize = 1024;
/// 플릿 하트비트 최소 전송 주기(5분).
const FLEET_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300);

/// 화면(IPC)에 보이는 작업 번호의 시작값. 서비스를 다시 시작해도 옛 번호와 겹치지 않게 시각에서 만든다.
/// 앱이 번호를 i32 로 다루므로 i32::MAX(약 21.4억) 아래에 머문다(약 23일 주기, 회차마다 1000개 여유).
pub(crate) fn wire_id_base(unix_secs: i64) -> u64 {
    (unix_secs.rem_euclid(2_000_000) as u64) * 1000
}

pub(crate) fn now_unix_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_else(|_| Local::now().timestamp() as f64)
}

/// 최근 잠금 충돌 뒤 쿨다운 중인가.
pub(crate) fn lock_busy_recently(p: &Profile, now_ts: f64) -> bool {
    p.extra
        .get("lock_busy_at")
        .and_then(|v| v.as_f64())
        .is_some_and(|t| now_ts - t >= 0.0 && now_ts - t < LOCK_BUSY_COOLDOWN_SEC)
}

/// 재시도가 아니라 정기 스케줄 자체가 도래했는가(재시도 한도를 다 쓴 것으로 보고 판정).
pub(crate) fn regular_slot_due(p: &Profile, now: DateTime<Local>) -> bool {
    let mut probe = p.clone();
    probe
        .extra
        .insert("retry_count".into(), (MAX_AUTO_RETRIES as u64).into());
    should_run(&probe, now)
}

/// 화면(IPC)으로 푸시되는 이벤트.
#[derive(Debug, Clone, PartialEq)]
pub enum SvcEvent {
    JobStarted {
        job_id: u64,
        profile_id: String,
        kind: Kind,
    },
    Progress {
        job_id: u64,
        percent: u64,
        current: String,
    },
    JobFinished {
        job_id: u64,
        profile_id: String,
        ok: bool,
        message: String,
        snapshot_id: Option<String>,
    },
}

/// 개별 작업 실행 결과(실행 이력 기록 및 완료 이벤트 발송에 공통 사용).
pub(crate) struct JobOutcome {
    pub ok: bool,
    pub message: String,
    pub snapshot_id: Option<String>,
    pub bytes: u64,
    pub files: u64,
}

impl JobOutcome {
    pub(crate) fn fail(message: String) -> Self {
        Self {
            ok: false,
            message,
            snapshot_id: None,
            bytes: 0,
            files: 0,
        }
    }
}

pub(crate) struct Shared {
    pub(crate) queue: Mutex<JobQueue>,
    pub(crate) subs: Mutex<Vec<SyncSender<SvcEvent>>>,
    pub(crate) wire_subs: Mutex<Vec<SyncSender<kova_ipc::Event>>>,
    pub(crate) store: ConfigStore,
    pub(crate) max_concurrent: usize,
    pub(crate) config_dir: PathBuf,
    /// 실행 중 작업의 취소 플래그(서비스 중지 때 모두 세운다). 이 잠금 안에서 `stopping` 을 확인하고 작업을 시작한다.
    pub(crate) running_flags: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    /// 정기 유지보수(Verify/Gc) 실패 시각(프로파일 ID 기준). 쿨다운 동안 정기 스케줄에서 재예약하지 않는다.
    pub(crate) maint_failed_at: Mutex<HashMap<String, Instant>>,
    /// 백그라운드 작업(복구 훈련·IPC 복원·클라우드 풀/정리) 실행 중 수. shutdown() 이 0 이 될 때까지 기다린다.
    pub(crate) active_bg: AtomicUsize,
    /// 현재 복구 훈련이 돌고 있는 프로파일 ID 집합(같은 프로파일에 훈련이 겹치지 않게).
    pub(crate) active_drills: Mutex<HashSet<String>>,
    /// 백그라운드 작업(IPC 복원·클라우드 풀/정리)의 취소 플래그 목록(shutdown() 때 모두 세운다).
    pub(crate) bg_cancels: Mutex<Vec<Arc<AtomicBool>>>,
    /// 서비스 중지 중: 새 작업을 시작하지 않는다.
    pub(crate) stopping: AtomicBool,
    /// 배터리 때문에 스케줄을 멈춘 상태(로그는 상태가 바뀔 때만 남긴다).
    pub(crate) on_battery: AtomicBool,
    /// IPC 로 보이는 작업 번호 = 내부 번호 + id_base
    pub(crate) id_base: u64,
    /// 마지막 플릿 하트비트 전송 시각.
    pub(crate) last_fleet_at: Mutex<Option<Instant>>,
}

pub(crate) struct BgGuard {
    shared: Arc<Shared>,
    drill_profile: Option<String>,
    cancel: Option<Arc<AtomicBool>>,
}

impl Drop for BgGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.drill_profile.take() {
            self.shared.active_drills.lock().unwrap().remove(&pid);
        }
        if let Some(flag) = self.cancel.take() {
            self.shared
                .bg_cancels
                .lock()
                .unwrap()
                .retain(|f| !Arc::ptr_eq(f, &flag));
        }
        self.shared.active_bg.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct Supervisor(pub(crate) Arc<Shared>);

impl Supervisor {
    pub fn new(config_dir: impl Into<PathBuf>, max_concurrent: usize) -> Self {
        let config_dir: PathBuf = config_dir.into();
        kova_core::repocrypto::install_provider(); // 암호화된 저장소를 열 때 쓸 키 제공자
        Self(Arc::new(Shared {
            queue: Mutex::new(JobQueue::new()),
            subs: Mutex::new(vec![]),
            wire_subs: Mutex::new(vec![]),
            store: ConfigStore::new(&config_dir),
            max_concurrent: max_concurrent.max(1),
            config_dir,
            running_flags: Mutex::new(HashMap::new()),
            maint_failed_at: Mutex::new(HashMap::new()),
            active_bg: AtomicUsize::new(0),
            active_drills: Mutex::new(HashSet::new()),
            bg_cancels: Mutex::new(vec![]),
            stopping: AtomicBool::new(false),
            on_battery: AtomicBool::new(false),
            id_base: wire_id_base(Local::now().timestamp()),
            last_fleet_at: Mutex::new(None),
        }))
    }

    pub fn subscribe(&self) -> Receiver<SvcEvent> {
        let (tx, rx) = sync_channel(SUB_CAPACITY);
        self.0.subs.lock().unwrap().push(tx);
        rx
    }

    pub(crate) fn subscribe_wire(&self) -> Receiver<kova_ipc::Event> {
        let (tx, rx) = sync_channel(SUB_CAPACITY);
        self.0.wire_subs.lock().unwrap().push(tx);
        rx
    }

    /// 구독자마다 유한한 채널로 보낸다. 가득 찬(읽지 않는) 구독자나 끊긴 구독자는 목록에서 뺀다.
    pub(crate) fn emit(&self, e: SvcEvent) {
        self.0
            .subs
            .lock()
            .unwrap()
            .retain(|s| s.try_send(e.clone()).is_ok());
        let mut wire_subs = self.0.wire_subs.lock().unwrap();
        if !wire_subs.is_empty() {
            let wire = ipc_handler::to_wire(e, self.0.id_base);
            wire_subs.retain(|s| s.try_send(wire.clone()).is_ok());
        }
    }

    pub(crate) fn maint_failed_recently(&self, profile_id: &str) -> bool {
        self.0
            .maint_failed_at
            .lock()
            .unwrap()
            .get(profile_id)
            .is_some_and(|t| t.elapsed() < MAINT_FAIL_COOLDOWN)
    }

    pub(crate) fn note_maint_failed(&self, profile_id: &str) {
        self.0
            .maint_failed_at
            .lock()
            .unwrap()
            .insert(profile_id.to_string(), Instant::now());
    }

    pub(crate) fn clear_maint_failed(&self, profile_id: &str) {
        self.0.maint_failed_at.lock().unwrap().remove(profile_id);
    }

    pub(crate) fn try_begin_drill(&self, profile_id: &str) -> Result<BgGuard, &'static str> {
        let mut drills = self.0.active_drills.lock().unwrap();
        self.0.active_bg.fetch_add(1, Ordering::SeqCst);
        if self.0.stopping.load(Ordering::SeqCst) {
            self.0.active_bg.fetch_sub(1, Ordering::SeqCst);
            return Err("서비스가 중지 중이라 복구 훈련을 시작할 수 없습니다");
        }
        if !drills.insert(profile_id.to_string()) {
            self.0.active_bg.fetch_sub(1, Ordering::SeqCst);
            return Err("이 프로파일의 복구 훈련이 이미 진행 중입니다");
        }
        Ok(BgGuard {
            shared: self.0.clone(),
            drill_profile: Some(profile_id.to_string()),
            cancel: None,
        })
    }

    pub(crate) fn try_begin_bg_cancellable(
        &self,
        action: &str,
    ) -> Result<(BgGuard, Arc<AtomicBool>), String> {
        let mut cancels = self.0.bg_cancels.lock().unwrap();
        if self.0.stopping.load(Ordering::SeqCst) {
            return Err(format!(
                "서비스가 중지 중이라 {action} 작업을 시작할 수 없습니다"
            ));
        }
        let cancel = Arc::new(AtomicBool::new(false));
        cancels.push(cancel.clone());
        self.0.active_bg.fetch_add(1, Ordering::SeqCst);
        Ok((
            BgGuard {
                shared: self.0.clone(),
                drill_profile: None,
                cancel: Some(cancel.clone()),
            },
            cancel,
        ))
    }

    pub(crate) fn try_begin_restore(&self) -> Result<(BgGuard, Arc<AtomicBool>), &'static str> {
        self.try_begin_bg_cancellable("복원")
            .map_err(|_| "서비스가 중지 중이라 복원을 시작할 수 없습니다")
    }

    /// 서비스 중지: 새 작업 시작을 막고 실행 중 작업에 취소를 알린 뒤 모두 끝날 때까지(최대 `limit`) 기다린다.
    /// 기다리는 동안 `on_wait` 를 주기적으로 부른다(서비스 상태 체크포인트 갱신용). 다 끝났으면 true.
    pub fn shutdown(&self, limit: Duration, mut on_wait: impl FnMut()) -> bool {
        {
            let flags = self.0.running_flags.lock().unwrap();
            self.0.stopping.store(true, Ordering::SeqCst);
            for f in flags.values() {
                f.store(true, Ordering::SeqCst);
            }
        }
        {
            let bg = self.0.bg_cancels.lock().unwrap();
            for f in bg.iter() {
                f.store(true, Ordering::SeqCst);
            }
        }
        let t = Instant::now();
        loop {
            if self.counts().1 == 0 && self.0.active_bg.load(Ordering::SeqCst) == 0 {
                return true;
            }
            if t.elapsed() >= limit {
                return false;
            }
            on_wait();
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    pub(crate) fn vss_marker(&self, job_id: u64) -> PathBuf {
        self.0.config_dir.join(format!("vss_inflight_{job_id}.txt"))
    }

    /// 섀도 복사본을 만들기 직전과 생성 직후에 기록을 남기고, 지운 뒤 기록을 지운다.
    /// 비정상 종료로 기록이 남으면 다음 시작 때 기록된 GUID 를 자동 정리하고 경고한다.
    pub(crate) fn mark_vss(&self, job_id: u64, what: &str, shadow_ids: &[String]) {
        let _ = std::fs::create_dir_all(&self.0.config_dir);
        let mut body = format!("{} {what}", Local::now().format("%Y-%m-%d %H:%M:%S"));
        for id in shadow_ids {
            body.push('\n');
            body.push_str(id);
        }
        let _ = std::fs::write(self.vss_marker(job_id), body);
    }

    pub(crate) fn unmark_vss(&self, job_id: u64) {
        let _ = std::fs::remove_file(self.vss_marker(job_id));
    }

    /// 수동 작업 요청 (화면에서 "지금 백업").
    pub fn enqueue(&self, profile_id: &str, kind: Kind) -> Enqueue {
        self.enqueue_with(profile_id, kind, "")
    }

    pub fn enqueue_with(&self, profile_id: &str, kind: Kind, arg: &str) -> Enqueue {
        let r = self
            .0
            .queue
            .lock()
            .unwrap()
            .enqueue_with(profile_id, kind, arg);
        self.pump();
        r
    }

    pub fn cancel(&self, job_id: u64) -> bool {
        self.0.queue.lock().unwrap().cancel(job_id)
    }

    /// 대기·실행 중인 작업의 종류(권한 판단용).
    pub fn job_kind(&self, job_id: u64) -> Option<Kind> {
        self.0.queue.lock().unwrap().kind_of(job_id)
    }

    fn maybe_send_fleet_heartbeat(&self, settings: &Settings) {
        let endpoint = settings.fleet_endpoint.trim();
        if endpoint.is_empty() {
            return;
        }
        {
            let mut last = self.0.last_fleet_at.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < FLEET_HEARTBEAT_INTERVAL) {
                return;
            }
            *last = Some(Instant::now());
        }
        let endpoint = endpoint.to_string();
        let cfg_dir = self.0.config_dir.clone();
        std::thread::spawn(move || {
            let hb = kova_core::fleet::build_heartbeat(&cfg_dir, env!("CARGO_PKG_VERSION"));
            if let Err(e) = kova_core::fleet::send_heartbeat(&endpoint, &hb) {
                kova_core::applog::write(
                    &cfg_dir,
                    "WARN",
                    &format!("Fleet 하트비트 전송 실패: {e}"),
                );
            }
        });
    }

    /// 스케줄이 도래한 프로파일을 큐에 넣고 시작 가능한 작업을 시작한다. 새로 큐에 넣은 수를 반환.
    pub fn tick(&self, now: DateTime<Local>) -> usize {
        let mut n = 0;
        if self.0.stopping.load(Ordering::SeqCst) {
            return 0;
        }
        let settings = self.0.store.settings();
        self.maybe_send_fleet_heartbeat(&settings);
        if settings.pause_on_battery && kova_core::schedule::is_on_battery() {
            if !self.0.on_battery.swap(true, Ordering::SeqCst) {
                kova_core::applog::write(
                    &self.0.config_dir,
                    "INFO",
                    "배터리 구동 중이라 자동 스케줄 백업을 일시정지합니다",
                );
            }
            return 0;
        }
        if self.0.on_battery.swap(false, Ordering::SeqCst) {
            kova_core::applog::write(
                &self.0.config_dir,
                "INFO",
                "배터리 일시정지를 풀고 자동 스케줄을 다시 시작합니다",
            );
        }
        let now_ts = now.timestamp() as f64;
        for p in self.0.store.profiles() {
            if lock_busy_recently(&p, now_ts) {
                continue;
            }
            // 백업이 오래 성공하지 못하면 하루에 한 번 경고 알림을 남긴다(조용히 멈춘 백업을 놓치지 않도록)
            if let Some(days) = kova_core::schedule::stale_days(&p, now, settings.stale_warn_days) {
                let last_warn = p.extra.get("last_stale_alert_at").and_then(|v| v.as_f64());
                if last_warn.is_none_or(|t| now_ts - t >= 86_400.0) {
                    let _ = kova_core::alerts::AlertLog::new(&self.0.config_dir).push(
                        kova_core::alerts::Alert {
                            at: now_ts,
                            profile_id: p.id.clone(),
                            level: "warning".into(),
                            message: format!(
                                "{}: {days}일째 백업 성공 기록이 없습니다 → 조치: 홈 화면에서 지금 백업을 실행하고, 실패하면 저장소 드라이브·원본 경로를 확인하세요.",
                                p.name
                            ),
                            acknowledged: false,
                        },
                    );
                    if let Some(mut fresh) = self.0.store.get(&p.id) {
                        fresh
                            .extra
                            .insert("last_stale_alert_at".into(), now_ts.into());
                        let _ = self.0.store.upsert(fresh);
                    }
                }
            }
            if should_run(&p, now) {
                // 정기 회차가 오면 재시도 횟수를 0으로 되돌린다(성공 때만 되돌리면 한 번 한도를 다 쓴 뒤 다시는 재시도하지 않음)
                if kova_core::schedule::retry_count(&p) > 0 && regular_slot_due(&p, now) {
                    if let Some(mut fresh) = self.0.store.get(&p.id) {
                        fresh.extra.insert("retry_count".into(), 0.into());
                        let _ = self.0.store.upsert(fresh);
                    }
                }
                let mut q = self.0.queue.lock().unwrap();
                if !q.is_profile_busy(&p.id) {
                    q.enqueue(&p.id, Kind::Backup);
                    n += 1;
                    continue;
                }
            }
            // 이미 스냅샷이 있는 프로파일에 대해 정기 Deep Scrub / 자동 GC 스케줄을 점검한다
            if p.last_snapshot_id.is_some() {
                let last_verify = p.extra.get("last_verify_at").and_then(|v| v.as_f64());
                let last_gc = p.extra.get("last_gc_at").and_then(|v| v.as_f64());
                if !self.maint_failed_recently(&p.id) {
                    let mut q = self.0.queue.lock().unwrap();
                    if !q.is_profile_busy(&p.id) {
                        if should_run_maintenance(
                            last_verify,
                            p.last_run,
                            settings.auto_verify_days,
                            now,
                        ) {
                            q.enqueue(&p.id, Kind::Verify);
                            kova_core::applog::write(
                                &self.0.config_dir,
                                "INFO",
                                &format!("정기 무결성 검증(Deep Scrub) 예약: profile={}", p.id),
                            );
                            n += 1;
                        } else if should_run_maintenance(
                            last_gc,
                            p.last_run,
                            settings.auto_gc_days,
                            now,
                        ) {
                            q.enqueue(&p.id, Kind::Gc);
                            kova_core::applog::write(
                                &self.0.config_dir,
                                "INFO",
                                &format!("정기 고아 블롭 정리(GC) 예약: profile={}", p.id),
                            );
                            n += 1;
                        }
                    }
                }
                // 주기 복구 훈련: 최근 스냅샷을 임시 폴더에 실제로 복원해 보고 결과를 남긴다(실패하면 알림)
                let last_drill = p.extra.get("last_drill_at").and_then(|v| v.as_f64());
                let idle = !self.0.queue.lock().unwrap().is_profile_busy(&p.id);
                if idle
                    && should_run_maintenance(last_drill, p.last_run, settings.auto_drill_days, now)
                {
                    if let Ok(guard) = self.try_begin_drill(&p.id) {
                        if let Some(mut fresh) = self.0.store.get(&p.id) {
                            fresh.extra.insert("last_drill_at".into(), now_ts.into());
                            let _ = self.0.store.upsert(fresh);
                        }
                        let me = self.clone();
                        let prof = p.clone();
                        std::thread::spawn(move || {
                            let _guard = guard;
                            let text = kova_core::drill::run(&prof, &std::env::temp_dir());
                            let pass = text.contains("통과");
                            let skipped =
                                text.contains("건너뜁니다") || text.contains("훈련할 수 없습니다");
                            kova_core::applog::write(
                                &me.0.config_dir,
                                if pass || skipped { "INFO" } else { "ERROR" },
                                &format!("정기 복구 훈련: {text}"),
                            );
                            if let Some(mut fresh) = me.0.store.get(&prof.id) {
                                fresh
                                    .extra
                                    .insert("last_drill_text".into(), text.clone().into());
                                let _ = me.0.store.upsert(fresh);
                            }
                            if !pass && !skipped {
                                let _ = kova_core::alerts::AlertLog::new(&me.0.config_dir).push(
                                    kova_core::alerts::Alert {
                                        at: Local::now().timestamp() as f64,
                                        profile_id: prof.id.clone(),
                                        level: "error".into(),
                                        message: kova_core::friendly::with_hint(&text),
                                        acknowledged: false,
                                    },
                                );
                            }
                        });
                    }
                }
            }
        }
        self.pump();
        n
    }

    /// (대기, 실행 중)
    pub fn counts(&self) -> (usize, usize) {
        self.0.queue.lock().unwrap().counts()
    }

    fn pump(&self) {
        loop {
            let started = {
                let mut flags = self.0.running_flags.lock().unwrap();
                if self.0.stopping.load(Ordering::SeqCst) {
                    break;
                }
                let s = self
                    .0
                    .queue
                    .lock()
                    .unwrap()
                    .start_next(self.0.max_concurrent);
                if let Some((job, flag)) = &s {
                    flags.insert(job.id, flag.clone());
                }
                s
            };
            let Some((job, flag)) = started else { break };
            let me = self.clone();
            std::thread::spawn(move || me.run_job(job, flag));
        }
    }

    fn run_job(&self, job: Job, cancel: Arc<AtomicBool>) {
        let started_at = now_unix_secs();
        kova_core::applog::write(
            &self.0.config_dir,
            "INFO",
            &format!(
                "작업 시작: id={} profile={} kind={:?}",
                job.id, job.profile_id, job.kind
            ),
        );
        self.emit(SvcEvent::JobStarted {
            job_id: job.id,
            profile_id: job.profile_id.clone(),
            kind: job.kind,
        });
        let _awake = SleepGuard::new(); // 작업 중 절전 진입 방지(이 작업 스레드에만 적용, 끝나면 자동 해제)
        let outcome = match job.kind {
            Kind::Backup => self.run_backup_job(&job, &cancel),
            Kind::Verify => self.run_verify_job(&job),
            Kind::Gc => self.run_gc_job(&job),
            Kind::Image(d) => self.run_image_job(&job, d, &cancel),
            Kind::DeleteSnapshot => self.run_delete_snapshot_job(&job),
        };
        let finished_at = now_unix_secs().max(started_at);
        // 모든 완료 작업을 SQLite 실행 이력 DB(job_history.db)에 기록한다
        if let Ok(db) = kova_core::history::JobHistoryDb::open(&self.0.config_dir) {
            let rec = kova_core::history::JobRunRecord {
                id: 0,
                started_at,
                finished_at,
                profile_id: job.profile_id.clone(),
                kind: ipc_handler::kind_name(job.kind),
                ok: outcome.ok,
                message: outcome.message.clone(),
                bytes: outcome.bytes,
                files: outcome.files,
            };
            if let Err(e) = db.record(&rec) {
                kova_core::applog::write(
                    &self.0.config_dir,
                    "WARN",
                    &format!("작업 이력 저장 실패: {e}"),
                );
            }
        }
        kova_core::applog::write(
            &self.0.config_dir,
            if outcome.ok { "INFO" } else { "ERROR" },
            &format!(
                "작업 종료: id={} profile={} kind={:?} ok={} msg={}",
                job.id, job.profile_id, job.kind, outcome.ok, outcome.message
            ),
        );
        // 실패·경고는 알림 기록에 남긴다(화면이 없는 서비스는 기록만, 표시는 앱이 한다). 사용자 취소는 알리지 않는다.
        // 저장소 잠금 충돌(다른 작업이 사용 중)은 일시적이라 알림·웹훅·이메일을 보내지 않는다.
        let busy = !outcome.ok && outcome.message.starts_with(BUSY_PREFIX);
        let cancelled = outcome.message == "취소됨" || outcome.message == "cancelled";
        let is_alert = !busy
            && !cancelled
            && (!outcome.ok
                || outcome.message.contains("복제 실패")
                || outcome.message.contains("이상 징후"));
        // 백업이 성공하면 같은 프로파일의 낡은 "N일째 성공 기록 없음" 경고는 자동으로 확인 처리한다.
        if outcome.ok && matches!(job.kind, Kind::Backup) {
            let _ =
                kova_core::alerts::AlertLog::new(&self.0.config_dir).resolve_stale(&job.profile_id);
        }
        if is_alert {
            let _ = kova_core::alerts::AlertLog::new(&self.0.config_dir).push(
                kova_core::alerts::Alert {
                    at: Local::now().timestamp() as f64,
                    profile_id: job.profile_id.clone(),
                    level: if outcome.ok { "warning" } else { "error" }.into(),
                    message: kova_core::friendly::with_hint(&outcome.message),
                    acknowledged: false,
                },
            );
        }
        // 원격 알림 발송(웹훅 + SMTP 이메일): 실패·경고 시 기본 발송, notify_on_success 가 켜져 있으면 성공 시에도 발송
        let st = self.0.store.settings();
        let should_notify =
            !busy && !cancelled && (is_alert || (st.notify_on_success && outcome.ok));
        if should_notify {
            let level = if !outcome.ok {
                "error"
            } else if is_alert {
                "warning"
            } else {
                "info"
            };
            let title = format!("프로파일 {} ({:?})", job.profile_id, job.kind);
            if !st.webhook_url.trim().is_empty() {
                let url = st.webhook_url.clone();
                let title_w = title.clone();
                let msg = outcome.message.clone();
                let cfg_dir = self.0.config_dir.clone();
                std::thread::spawn(move || {
                    if let Err(e) = kova_core::notify::send_webhook(&url, level, &title_w, &msg) {
                        kova_core::applog::write(&cfg_dir, "WARN", &format!("웹훅 발송 실패: {e}"));
                    }
                });
            }
            if let Ok(Some(smtp_cfg)) = kova_core::smtp::load_config(&self.0.config_dir) {
                let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
                let subject = format!("[Kova2][{level}][{host}] {title}");
                let body = format!(
                    "호스트: {host}\n작업: {title}\n결과: {}\n내용: {}",
                    if outcome.ok { "성공" } else { "실패" },
                    outcome.message
                );
                let cfg_dir = self.0.config_dir.clone();
                std::thread::spawn(move || {
                    if let Err(e) = kova_core::smtp::send_email(&smtp_cfg, &subject, &body) {
                        kova_core::applog::write(
                            &cfg_dir,
                            "WARN",
                            &format!("SMTP 이메일 발송 실패: {e}"),
                        );
                    }
                });
            }
        }
        // 이벤트를 먼저 보낸 뒤 큐에서 빼야 "큐가 비었다 = 모든 이벤트가 나갔다"가 성립한다
        self.emit(SvcEvent::JobFinished {
            job_id: job.id,
            profile_id: job.profile_id.clone(),
            ok: outcome.ok,
            message: outcome.message,
            snapshot_id: outcome.snapshot_id,
        });
        if busy {
            self.note_lock_busy(&job.profile_id);
        }
        self.0.running_flags.lock().unwrap().remove(&job.id);
        self.0.queue.lock().unwrap().finish(job.id);
        self.pump();
    }

    /// 잠금 충돌을 프로파일에 기록해 정기 스케줄이 쿨다운 동안 다시 큐에 넣지 않게 한다(없어진 프로파일은 되살리지 않음).
    fn note_lock_busy(&self, profile_id: &str) {
        if let Some(mut p) = self.0.store.get(profile_id) {
            p.extra.insert(
                "lock_busy_at".into(),
                (Local::now().timestamp() as f64).into(),
            );
            let _ = self.0.store.upsert(p);
        }
    }
}

/// 살아 있는 동안 시스템이 절전으로 들어가지 않게 한다(스레드 단위, Drop 시 해제).
pub struct SleepGuard;
#[cfg(windows)]
extern "system" {
    fn SetThreadExecutionState(flags: u32) -> u32;
}
impl SleepGuard {
    pub fn new() -> Self {
        #[cfg(windows)]
        unsafe {
            // ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            SetThreadExecutionState(0x8000_0000 | 0x0000_0001);
        }
        SleepGuard
    }
}

impl Default for SleepGuard {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for SleepGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            SetThreadExecutionState(0x8000_0000); // ES_CONTINUOUS 만 → 요구 해제
        }
    }
}

/// 설정 폴더: %ProgramData%\Kova2\config (없으면 현재 폴더 아래)
pub fn default_config_dir() -> PathBuf {
    // 시험·통합 검증용 재지정(실제 설정 폴더를 건드리지 않기 위함)
    if let Some(d) = std::env::var_os("KOVA2_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Kova2")
        .join("config")
}

/// 스케줄러 틱 스레드: 30초마다 도래한 프로파일을 큐에 넣는다. 시작 직후 한 번 돌아 놓친 백업을 따라잡는다.
pub fn spawn_scheduler(sup: Supervisor, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            sup.tick(Local::now());
            for _ in 0..60 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    })
}

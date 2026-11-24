//! Windows PowerShell 기반 폴더·파일 선택 창(무창 실행).
use crate::util::BusyGate;
use crate::{MainWindow, PickBus};
use slint::ComponentHandle;

const FOLDER_PICKER_CS: &str = r#"using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class FP {
  [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")] class FOD {}
  [ComImport, Guid("42f85136-db7e-439c-85f1-e4075d135fc8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IFileOpenDialog {
    [PreserveSig] int Show(IntPtr h);
    void SetFileTypes(uint c, IntPtr f);
    void SetFileTypeIndex(uint i);
    void GetFileTypeIndex(out uint i);
    void Advise(IntPtr p, out uint c);
    void Unadvise(uint c);
    void SetOptions(uint o);
    void GetOptions(out uint o);
    void SetDefaultFolder(IShellItem s);
    void SetFolder(IShellItem s);
    void GetFolder(out IShellItem s);
    void GetCurrentSelection(out IShellItem s);
    void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string n);
    void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string n);
    void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string t);
    void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string t);
    void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string t);
    void GetResult(out IShellItem s);
    void AddPlace(IShellItem s, int f);
    void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string e);
    void Close(int hr);
    void SetClientGuid(ref Guid g);
    void ClearClientData();
    void SetFilter(IntPtr f);
    void GetResults(out IShellItemArray a);
    void GetSelectedItems(out IShellItemArray a);
  }
  [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IShellItem {
    void BindToHandler(IntPtr p, ref Guid b, ref Guid r, out IntPtr o);
    void GetParent(out IShellItem s);
    void GetDisplayName(uint n, [MarshalAs(UnmanagedType.LPWStr)] out string s);
    void GetAttributes(uint m, out uint a);
    void Compare(IShellItem s, uint h, out int o);
  }
  [ComImport, Guid("b63ea76d-1f85-456f-a19c-48159efa858b"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IShellItemArray {
    void BindToHandler(IntPtr p, ref Guid b, ref Guid r, out IntPtr o);
    void GetPropertyStore(int f, ref Guid r, out IntPtr o);
    void GetPropertyDescriptionList(IntPtr k, ref Guid r, out IntPtr o);
    void GetAttributes(int f, uint m, out uint a);
    void GetCount(out uint c);
    void GetItemAt(uint i, out IShellItem s);
    void EnumItems(out IntPtr e);
  }
  public static string[] Pick(bool multi, IntPtr owner) {
    var d = (IFileOpenDialog)new FOD();
    uint o; d.GetOptions(out o);
    d.SetOptions(o | 0x20u | 0x40u | (multi ? 0x200u : 0u));
    d.SetTitle(multi ? "폴더 선택 (여러 개 선택 가능)" : "폴더 선택");
    int hr = d.Show(owner);
    if (hr == unchecked((int)0x800704C7)) return new string[0]; // 사용자가 취소
    if (hr != 0) Marshal.ThrowExceptionForHR(hr);
    var l = new List<string>();
    IShellItemArray a = null;
    try { d.GetResults(out a); } catch (Exception) { a = null; }
    if (a != null) {
      uint c; a.GetCount(out c);
      for (uint i = 0; i < c; i++) { IShellItem s; a.GetItemAt(i, out s); string p; s.GetDisplayName(0x80058000u, out p); l.Add(p); }
    } else {
      IShellItem s1; d.GetResult(out s1); string p1; s1.GetDisplayName(0x80058000u, out p1); l.Add(p1);
    }
    return l.ToArray();
  }
}"#;

/// 폴더 선택 창용 C# 어셈블리를 캐시하는 경로(처음 한 번만 컴파일하고 이후에는 읽기만 한다).
fn folder_picker_dll() -> std::path::PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("Kova2")
        .join(format!("fp_{}.dll", FOLDER_PICKER_CS.len()))
}

/// 선택 창을 띄우는 PowerShell 스크립트.
pub(crate) fn build_pick_script(kind: &str) -> String {
    // 폴더 선택은 탐색기와 같은 최신 선택 창(IFileOpenDialog). "folders" 는 여러 폴더를 한 번에 고른다.
    if kind == "folder" || kind == "folders" {
        let dll = folder_picker_dll().to_string_lossy().replace('\'', "''");
        return format!(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';$dll='{dll}';\
             if(-not (Test-Path -LiteralPath $dll)){{New-Item -ItemType Directory -Force -Path (Split-Path $dll) | Out-Null;\
             Add-Type -TypeDefinition @'\n{FOLDER_PICKER_CS}\n'@ -OutputAssembly $dll}};\
             Add-Type -Path $dll;Add-Type -AssemblyName System.Windows.Forms;\
             $f=New-Object Windows.Forms.Form;$f.TopMost=$true;$f.ShowInTaskbar=$false;$f.FormBorderStyle='None';\
             $f.StartPosition='CenterScreen';$f.Opacity=0;$f.Size=New-Object Drawing.Size(1,1);$f.Show();\
             [FP]::Pick(${multi},$f.Handle) | ForEach-Object {{ $_ }}",
            multi = if kind == "folders" { "true" } else { "false" }
        );
    }
    let (cls, filter, ext) = match kind {
        "qblk-open" => (
            "OpenFileDialog",
            "Kova 이미지 (*.qblk;*.qblk.enc)|*.qblk;*.qblk.enc|모든 파일|*.*",
            "",
        ),
        "qblk-save" => ("SaveFileDialog", "Kova 이미지 (*.qblk)|*.qblk", "qblk"),
        "img-save" => (
            "SaveFileDialog",
            "디스크 이미지|*.img;*.raw;*.vhd;*.vhdx;*.bin",
            "img",
        ),
        _ => (
            "OpenFileDialog",
            "디스크 이미지|*.img;*.raw;*.bin;*.vhd|모든 파일|*.*",
            "",
        ),
    };
    format!(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Windows.Forms;$f=New-Object Windows.Forms.Form;$f.TopMost=$true;\
         $d=New-Object Windows.Forms.{cls};$d.Filter='{filter}';$d.DefaultExt='{ext}';if($d.ShowDialog($f)-eq'OK'){{$d.FileName}}"
    )
}

/// PowerShell 이 낸 여러 줄(여러 폴더)을 ';' 로 이어 한 칸에 넣는다. 줄 끝 공백·빈 줄·맨 앞 BOM(U+FEFF)은 버린다.
pub(crate) fn parse_picked(stdout: &str) -> String {
    stdout
        .lines()
        .map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}'))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(";")
}

/// Windows 폴더/파일 선택 창(PowerShell, 창 없이 실행). 취소하면 빈 문자열, 창을 못 열면 오류 문구.
pub(crate) fn pick_path(kind: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let script = build_pick_script(kind);
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut enc = String::new();
    for c in utf16.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                enc.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                enc.push('=');
            }
        }
    }
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-STA",
            "-NoProfile",
            "-NonInteractive",
            "-OutputFormat",
            "Text",
            "-EncodedCommand",
            &enc,
        ])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        // 캐시된 어셈블리가 깨졌을 수 있으니 지워서 다음 번에 다시 만들게 한다
        let _ = std::fs::remove_file(folder_picker_dll());
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().map(str::trim).find(|l| !l.is_empty());
        return Err(first
            .unwrap_or("PowerShell 실행 실패")
            .chars()
            .take(80)
            .collect());
    }
    Ok(parse_picked(&String::from_utf8_lossy(&out.stdout)))
}

/// '찾아보기' 결과를 어디에 어떻게 넣을지. 대상 이름(target)은 main.slint 의 browse 호출 쪽에서 정한다.
#[derive(Debug, PartialEq)]
pub(crate) enum PickPlan {
    /// 취소(빈 결과)·대상 없음: 기존 값을 그대로 둔다.
    Keep,
    /// 선택 창을 못 열었다: pick-error 에 표시하고 기존 값은 그대로 둔다.
    Error(String),
    /// 백업 편집 원본 목록에 더한다(form-add).
    FormAdd(String),
    /// target 이 같은 PathField 입력 칸에 넣는다(PickBus).
    Field(String, String),
}

/// 선택 결과와 대상 이름으로 반영 방법을 정한다(순수 함수).
pub(crate) fn pick_plan(target: &str, res: Result<String, String>) -> PickPlan {
    match res {
        Err(e) => PickPlan::Error(format!("선택 창을 열지 못했습니다: {e}")),
        Ok(p) if p.trim().is_empty() => PickPlan::Keep,
        Ok(p) => match target {
            "form-add" => PickPlan::FormAdd(p),
            "" => PickPlan::Keep,
            t => PickPlan::Field(t.to_string(), p),
        },
    }
}

/// UI 스레드에서 선택 결과를 반영한다. 오류가 아니면 이전 오류 표시는 지운다.
pub(crate) fn apply_pick(w: &MainWindow, plan: PickPlan) {
    let err = match &plan {
        PickPlan::Error(e) => e.clone(),
        _ => String::new(),
    };
    w.set_pick_error(err.into());
    match plan {
        PickPlan::FormAdd(p) => w.invoke_form_add(p.into()),
        PickPlan::Field(t, p) => {
            let bus = w.global::<PickBus>();
            bus.set_target(t.into());
            bus.set_value(p.into());
            bus.set_seq(bus.get_seq().wrapping_add(1));
        }
        PickPlan::Keep | PickPlan::Error(_) => {}
    }
}

pub(crate) fn wire(w: &MainWindow) {
    // 선택 창(PowerShell, 첫 실행은 C# 컴파일)은 별도 스레드에서 열어 창이 멈추지 않게 하고, 결과는 UI 스레드에서 넣는다
    let weak = w.as_weak();
    let gate = BusyGate::default();
    w.on_browse(move |k, target| {
        if !gate.try_begin() {
            return; // 이미 선택 창이 떠 있다
        }
        let (weak, gate) = (weak.clone(), gate.clone());
        let (kind, target) = (k.to_string(), target.to_string());
        std::thread::spawn(move || {
            let plan = pick_plan(&target, pick_path(&kind));
            let _ = slint::invoke_from_event_loop(move || {
                gate.end();
                if let Some(w) = weak.upgrade() {
                    apply_pick(&w, plan);
                }
            });
        });
    });
}

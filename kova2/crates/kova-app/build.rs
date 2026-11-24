const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    slint_build::compile("ui/main.slint").unwrap();
    // 탐색기·바로가기·작업 표시줄에 보이는 exe 아이콘 및 Windows 긴 경로(longPathAware) 매니페스트
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/kova.ico");
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/kova.ico");
        res.set_manifest(MANIFEST);
        res.compile().unwrap();
    }
}

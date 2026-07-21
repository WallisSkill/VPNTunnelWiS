# Tinh trang

Chay that. Tunnel len, hai chieu deu co luu luong, remote desktop vao may trong cong ty
duoc, on dinh. Khong can FortiClient, khong can quyen admin.

## Kien truc

Ba tang, moi tang go mot cho Windows tu choi:

    FortiVpnHost.exe   host UWP viet bang C++ (/SUBSYSTEM:WINDOWS /APPCONTAINER)
      -> FortiVpnShim.dll   WinRT in-process server, tu khoi dong CoreCLR qua hostfxr
        -> FortiVpnPlugin.dll   lop FortiPlugin, IVpnPlugIn + IBackgroundTask

- Host phai la native: .NET console host bi tu choi ngay khi khoi dong
  (E_APPLICATION_ACTIVATION_EXEC_FAILURE 0x8027025B). App model bat buoc anh phai duoc
  danh dau `/APPCONTAINER`, va handshake kich hoat nam trong `CoreApplication::Run`.
- Shim phai tu goi hostfxr: `WinRT.Host.dll` cua CsWinRT tra 0x80008093 cho moi
  `DllGetActivationFactory` ma khong he khoi dong runtime (platform bao lai thanh
  0x80073CFC, kho doan hon nhieu).
- Runtime khoi dong tu chinh `dist\` chu khong tu may: layout la ban publish
  self-contained, shim nap `hostfxr.dll` nam canh no. Nhung
  `hostfxr_initialize_for_runtime_config` tu choi thang config self-contained
  (0x80008093, HostApiUnsupportedScenario) vi config do khong tham chieu framework nao
  ca, chi "included". Duong vao cho hinh dang do la
  `hostfxr_initialize_for_dotnet_command_line` tren `FortiVpnHost.dll` -- khong chay gi
  cua app, chi khoi tao. Nho vay goi khong can .NET cai san tren may.
- Manifest chi khai **mot** dang ky in-process. Mot lop khong duoc khai ca in-process
  lan out-of-process (deployment tra 0x800700A0), va chinh no la ly do truoc day
  platform cho mai mot dang ky khong bao gio den (0x8027025A). `ServerName` van giu vi
  task `vpnClient` bi tu choi neu thieu, nhung khong can server that dung sau no.

## Bon loi data-plane da sua

Ca bon deu cho ra cung mot trieu chung: tunnel bao Connected ma khong tai gi.

1. **`foreach` tren `VpnPacketBufferList`** nem `InvalidCastException` tu
   `GetEnumerator()` -- kieu nay khong implement `IIterable`. Moi goi gui deu mat truoc
   khi kip dong khung. Phai rut bang `while (list.Size > 0) list.RemoveAtBegin()`.
2. **Can kiet pool buffer gui.** Buffer lay ra khoi danh sach vao phai duoc `Append`
   tro lai; nhanh du phong cu lay ra mot cai roi tra ve mot cai khac, ro ri dan, va
   duong gui dung han sau chung mot chuc goi.
3. **App container bi treo.** Xong background task cuoi cung la Process Lifetime
   Management dinh chi ca tien trinh. Do truc tiep: ca 17 thread cua host o trang thai
   `Wait, Suspended`, CPU dung yen, khong mot dong heartbeat nao, ping qua tunnel mat
   100% trong khi Windows van bao Connected. `Encapsulate` khong chay noi trong mot tien
   trinh bi dinh chi, nen goi ra khong bao gio duoc dong khung va khong co gi tro ve.
   Phai luon co mot activation con no deferral -- xem "Deferral" ben duoi.
4. **Khung tran buffer.** Platform cap buffer gui dung bang MTU khai bao, nen goi
   full-size khong bao gio chua noi header 8 byte cua chinh no; ha MTU vo ich vi buffer
   co lai theo. Transport la luong byte chu khong phai datagram, nen header di rieng
   thanh mot buffer dung ngay truoc goi IP con nguyen, hai cai gap lai tren day.

## Ghi nho

- `LogDiagnosticMessage` doi kenh chi admin moi bat duoc. Moi chan doan ghi ra
  `%TEMP%\forti-plugin.log` **ben trong** container:
  `%LOCALAPPDATA%\Packages\FortiGateSslVpn.Plugin_ze06k0zwcba52\AC\Temp\`.
  `Trace` phai co khoa: hai luong ghi cung luc lam mat ca hai dong vi sharing violation,
  doc ra y het "Encapsulate khong he duoc goi".
- `AssociateTransport` phai goi **truoc** khi socket connect. Socket da connect bi tra
  E_ILLEGAL_STATE_CHANGE, noi ra thanh `InvalidOperationException`.
- Platform tao mot doi tuong `FortiPlugin` moi cho **moi** su kien. Moi trang thai bac
  cau qua nhieu su kien phai `static`.
- Khung Fortinet: `[0..1]` tong do dai BE = 6+len, `[2..3]` magic 0x5050, `[4..5]` do dai
  payload, `[6..7]` PPP proto, roi than. Khong HDLC, khong FCS, khong FF 03.
- Gateway nay khong tra `<dns>`, `<split-tunnel-info>` rong, nen `dns=[]` la that chu
  khong phai loi parse: phai remote bang IP, khong dung ten may.
- `GetKeepAlivePayload` chua bao gio duoc goi.
- `RequestCredentials` tra ve tu **cache** neu khong danh dau la retry, va platform cache
  ca cai vua bi gateway tu choi. Go mot lan sai mat khau la moi lan quay so sau do deu
  gui lai dung cai sai do, nguoi dung khong he duoc hoi lai. Phai nho lai va lan sau xin
  voi `isRetry: true`. Nhung dang retry khong phai luc nao cung co: quay bang `rasdial`
  kem san tai khoan thi no nem `0x80070032` (ERROR_NOT_SUPPORTED), nen phai fallback ve
  dang thuong chu khong duoc de hong ca cuoc goi.
- **Co `_credentialRejected` phai duoc *tieu thu*, khong duoc de dung mai.** "Retry" la
  lenh cho dung mot cuoc quay so. De `static` va khong ha xuong thi no song lau hon cai
  loi go nham da dat no len: moi cuoc quay so sau do trong cung tien trinh deu xin voi
  `isRetry: true`, ma dang do **vut ca cache di** -- ke ca tai khoan/mat khau nguoi dung
  da dien san o Settings > Add VPN va duoc giu lai nho `RememberCredentials`. Doc ra
  thanh "ban SSL khong cho dien san tai khoan, lan nao cung bat go lai": no co cho dien,
  va chinh cho nay vut di. Nay `FetchCredentials` doc va ha co trong cung mot buoc
  `Interlocked` -- dung mot lan retry, roi ve lai cache.
- Bat tay co han 25 giay. Khong co han thi mot gateway bat tay TLS xong roi im lang
  (dung kieu FortiOS chan nguon da sai mat khau vai lan) se treo luon thread trong mot
  lenh doc, va nguoi dung chi thay "timeout" khong ly do.
- Moi chuoi nguoi dung thay -- `SetErrorMessage`, `Trace`, log cua script -- deu bang
  tieng Anh.
- **Failed dials must not dispose their own session.** The socket has already been through
  `AssociateTransport` by the time a login is refused, and closing it from the failure path
  leaves the channel holding a dead transport: the *next* dial then completes the whole
  handshake, brings the tunnel up, sends packets and receives nothing at all. The session is
  disposed at the start of the following `Connect` instead, which also ends the read a
  timed-out handshake left parked on it.
- **A cancel that is not answered kills the host process, not just the task.** While the
  tunnel's background task held its deferral it got a cancel notification; ignoring it
  produced `BrokerInfrastructure` event 6 ("did not complete in response to a cancel
  notification"), the host was terminated, and RAS reported 829 -- a live session dropping
  roughly ninety seconds in, with no `Disconnect` and no clue in the plugin log.
- **Deferral phai luan phien, khong the giu mai ma cung khong the bo han.** Bon buoc bang
  chung, theo dung thu tu:
  1. Giu mot deferral suot doi tunnel: *mot* activation phuc vu ca tunnel, chay tot.
  2. Den ~90 giay platform huy no voi `ExecutionTimeExceeded`. Vay mot deferral khong the
     do het doi tunnel du co muon.
  3. Lo di cai huy do thi mat ca tien trinh host (829 o tren).
  4. Bo han khong giu deferral nao -- dung mau Microsoft -- thi container bi dinh chi va
     tunnel chet cung: do duoc ca 17 thread `Wait, Suspended`, ping mat 100%. Luu luong
     "van chay" o lan do la hieu ung phu: goi **gui ra** danh thuc container, nen chi
     nhung goi den dung luc thuc day moi qua duoc, ping tra ve cham hang phut. Ghi trong
     tai lieu nay truoc do rang "dinh chi vo hai" la sai, nhac lai cho ro.

  5. Tra deferral lai *khi bi huy* cung khong du. `ExecutionTimeExceeded` khong chi ket
     thuc mot activation -- no giet luon duong du lieu cua channel trong ca doi tien
     trinh. Do duoc: `sent=1874 received=1602` dang tang deu, cancel luc 11:09:58, roi hai
     con so do dung y nguyen suot sau phut ke tiep trong khi heartbeat van danh. Moi lan
     quay so lai trong cung tien trinh do deu duoc mot tunnel `received=0`. Va platform
     quay so lai sau moi lan cancel -- do chinh la canh "cu connect roi disconnect" nhin
     tu ngoai.

  Nen deferral duoc **luan phien theo dong ho cua chinh minh**: activation nao thay chua
  ai giu thi xung phong giu, va tu tra lai sau 60 giay -- lan cancel do duoc la 89.7 giay,
  nen 60 la an toan va `ExecutionTimeExceeded` khong bao gio den. Tra ra thi platform
  quay ve kich hoat theo tung goi, va goi ke tiep giao cai giu cho mot activation moi voi
  90 giay moi. Moi deferral chi duoc `Complete` mot lan (lop `Activation` giu co
  `Interlocked`), va **dung activation bi huy** moi duoc tra deferral cua no -- tra nham
  cua thang khac la de lai mot cai huy khong ai dap, tuc la mat tien trinh.

  6. **Va luan phien theo dong ho cung chua du: khong duoc giu hold qua luc tunnel ranh.**
     Do duoc trong mot phien that: bo dem dung yen o `sent=451999 received=555016` suot
     50 phut, kem hai lan `ExecutionTimeExceeded` luc 23:13:18 va 23:41:18. Trinh tu:

         22:58:20  mot activation nhan hold, dat timer 60 giay
                   container bi dinh chi -- timer dong bang theo
         23:13:01  container thuc lai (heartbeat chay lai), da giu ~14,7 phut
         23:13:18  ExecutionTimeExceeded

     `System.Threading.Timer` **khong chay khi container bi dinh chi**, nhung 90 giay cua
     platform la **wall-clock**. Nen hold nao roi vao mot lan dinh chi la chac chan vuot
     han, va thu doc dong ho luc thuc day cung vo ich: den luc do platform da huy tu lau.

     Vong luan quan lam no tu duy tri: tunnel chet -> khong co goi -> khong co activation
     -> khong ai nhan hold -> container ngu -> tunnel cang chet.

     Nen hold chi duoc nhan va giu **khi duong du lieu con chay**. Im qua 30 giay thi tha
     ra, cho container ngu ma **khong no deferral** nao. Danh doi la do tre cua goi gui ra
     dau tien sau luc ranh (goi gui ra danh thuc container); doi lai la khong bao gio gap
     `ExecutionTimeExceeded` nua -- ma cai do giet duong du lieu cua channel trong ca doi
     tien trinh, khong cuu duoc. Ngu duoc thi tinh lai; bi huy thi phai ha tien trinh.

     Timer xoay doi tu one-shot sang **dinh ky 5 giay va tu doc lai wall-clock**, vi mot
     one-shot do bang thoi gian tien trinh khong bao gio den han sau mot lan dinh chi.
     `heartbeat` nay in kem `idle=` -- bo dem dung yen mot minh khong noi duoc tunnel dang
     ranh hay dang ket.
- **Heartbeat la den bao.** Mot dong moi 10 giay. Im lang trong log khi tunnel dang len
  nghia la container da ngu -- dau hieu duy nhat nhin thay duoc tu ben trong. Kem theo la
  `rotating the hold` moi 60 giay; thay du ca hai va `received=` van tang la tunnel lanh.
- **Windows khong bao gio goi `Disconnect`.** Khong mot dong `FortiPlugin.Disconnect` nao
  xuat hien trong bat ky log nao -- Windows ha thang tien trinh host. Nen gateway khong he
  biet phien da xong, va no giu lai theo `tun-user-ses-timeout='30'` voi `check-src-ip='1'`:
  dang nhap lai tu cung IP trong 30 giay do bi **im lang**, dung cham han 25 giay cua buoc
  bat tay, va doc ra thanh "timeout" khong ly do. Do la trieu chung "ngat roi noi lai la
  timeout". Nay `Connect` gui `GET /remote/logout` kem cookie cu **truoc** khi bo session
  cu, tren mot socket rieng (socket cu da thuoc ve platform, viet HTTP vao do la hong luon
  luong khung). Han 3 giay, nuot moi loi. Chi cuu duoc truong hop noi lai trong **cung mot
  tien trinh**; tien trinh bi ha thi cookie mat theo va van phai doi het 30 giay -- nen
  thong bao timeout noi thang ra dieu do.
- **Quay so thu bang tai khoan rac cung phai tra gia.** FortiOS dem do la dang nhap sai va
  chan nguon sau vai lan, chan kieu bat tay TLS xong roi im -- lai ra dung cai "timeout"
  o tren. Kiem tra build bang cach doc log phien that, dung tu dial.
- **Platform goi `Connect` hai lan cho cung mot cuoc quay so**, hai activation cach nhau
  vai mili giay, lan nao reconnect cung thay. Thang thua chay den `RequestCredentials` thi
  duoc tra `0x8007048F` roi bao that bai len dung cai channel ma thang thang sap khoi dong.
  Nay co co `_connecting`: chi thang dau tien lam viec, thang sau lang le rut.
- **Log phai re.** Voi ~2600 activation/phut, moi dong log mo/ghi/dong mot file duoi mot
  khoa toan cuc la khong tra noi. `Trace` giu san mot `StreamWriter`
  (`FileShare.ReadWrite`, `AutoFlush`) suot doi tien trinh, va `Run` chi noi to cho 8
  activation dau roi mot dong moi 1000 cai.
- **`ProcessEventAsync` returns while the handler is still running.** Measured: it came back
  4 ms after `Connect` was entered, and `Connect` ran for another 150 ms. Anything the
  handler writes at the end of its work is read stale by `Run`'s `finally` -- which is what
  made the deferral handoff above unworkable in the first place.
- Dong dau tien cua `Connect` phai la mot dong log, truoc ca khi doc profile. Doc
  `channel.Configuration` cung la mot loi goi nguoc ve platform, nen neu treo o do thi log
  in sau no khong bao gio hien, va nham y het voi "platform khong he goi Connect".
- **`ProcessEventAsync` phai duoc dua doi tuong da phuc vu `Connect`, khong phai `this`.**
  Platform dung **mot `FortiPlugin` moi cho moi activation** -- danh so ra thi mot cuoc
  ket noi roi ngat di qua `obj#1`, `obj#2`, `obj#3`, `obj#4`. Channel thuoc ve doi tuong
  da phuc vu `Connect` (`obj#1`); dua cho `ProcessEventAsync` mot doi tuong la thi su kien
  toi noi nhung khong dispatch duoc di dau.

  Trieu chung khong he giong nguyen nhan: nguoi dung thay **"Disconnecting" dung 15 giay**,
  lan nao cung the. `Disconnect` khong bao gio duoc goi, va vi khong ai bao plugin biet
  nen cung khong co gi trong log de lan. Do bang ETW provider
  `Microsoft-Windows Networking VPN Plugin Platform`
  (`{E5FC4A0F-7198-492F-9B0F-88FDCBFDED48}`) moi thay day du:

      00:51:52.403  platform  2002 "Disconnect"
      00:51:52.404  platform  2022 bat dau
      00:51:52.424  plugin    Run activation 7 -- su kien CO toi
      00:51:52.425  plugin    ProcessEventAsync tra ve sau 1ms, khong dispatch
      00:52:07.449  platform  2023 -- bo cuoc sau 15.045 giay

  15 giay do la **timeout cua platform**, khong phai cong viec that. RAS ghi nhan ngat sau
  0,13 giay; toan bo phan con lai la platform ngoi cho mot `Disconnect` khong bao gio den.
  Sau khi luon dua `obj#1`: `Disconnect` chay het **0 ms**, RAS ghi nhan sau **24 ms**.

  Ba huong da duoi va deu sai, ghi lai de khoi duoi lai: (1) plugin giu deferral lam
  platform khong thu hoi duoc -- cat hold tu 31 giay xuong 5,6 giay, dong ho khong nhuc
  nhich; (2) giao dien Settings hien cham chu ket noi da dut -- `rasdial /disconnect` cung
  dung 15,08 giay; (3) trigger details khong project duoc (`WinRT.IInspectable`) -- chinh
  duong `Connect` chay duoc cung in ra kieu do.

  Bai hoc chung: moi field trong `FortiPlugin` da phai `static` **chinh vi** doi tuong bi
  dung moi lien tuc. Cai bi bo sot la `ProcessEventAsync` nhan doi tuong chu khong nhan
  state, nen `static` khong cuu duoc no.

## Cai dat

    powershell -ExecutionPolicy Bypass -File build.ps1      # dung dist\
    powershell -ExecutionPolicy Bypass -File install.ps1    # dang ky provider
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
    powershell -ExecutionPolicy Bypass -File package.ps1    # out\FortiVpnPlugin-<ver>.zip
    powershell -ExecutionPolicy Bypass -File installer.ps1  # out\FortiVpnSetup-<ver>.exe

`install.ps1` khong tao ket noi nao. No chi dang ky package de "FortiGate SSL-VPN" hien
ra trong danh sach VPN provider; nguoi dung tu them ket noi trong Settings, va plugin
doc dia chi gateway ra tu profile do.

**Dia chi phai go dang `https://host:port`.** Day khong phai so thich trinh bay, ma la
cho duy nhat plugin doc lai duoc. Settings nhan `host:port` tran khong he bao gi, nhung
ca hai duong dua dia chi vao app container deu chet voi no:

- `ServerHostNameList` -- platform dung tung phan tu bang `HostName(String)`, ma
  `HostName` khong nhan dau hai cham. Doc vector nem `E_INVALIDARG` ("The parameter is
  incorrect. hostName") truoc khi giao ra phan tu nao. Duong nay chi con dung cho profile
  ghi dia chi khong kem port.
- `ServerUris` -- `System.Uri` doc `118.x.x.x:8080` thanh scheme `118.x.x.x`, nem
  `Invalid URI: The URI scheme is not valid.`. Them `https://` vao thi parse dung ca host
  lan port. Nem ngay luc doc vector nen khong loc rieng phan tu hong duoc.

`CustomField` (the `<serverUrl>`) duoc thu truoc ca hai, nhung profile tao tu Settings de
trong -- no chi co gia tri khi profile duoc dung bang tay. `ServerServiceName` chi duoc
hoi den khi dia chi khong kem port, va thuong doc ra "0".

Truoc day cho nay khong lo ra vi `ResolveServer` co hang so gateway de roi ve; bo hang so
di (de day len git) moi thay no chua bao gio doc duoc profile that.

Khong ky MSIX, khong `makeappx`: goi da ky chi cai duoc khi chung thu nam trong
LocalMachine\Root, ma viec do can admin. Layout dang ky truc tiep thi khong.

`package.ps1` gop `dist\` + hai script + `docs\readme-package.md` thanh mot zip (~42 MB)
dua cho may khac dung duoc nguyen ven, khong tai them gi.

`installer.ps1` ra mot file `.exe` duy nhat (~42 MB) mang nguyen `dist\` da nen ben trong
lam resource. No lam dung viec cua `install.ps1` nhung khong can PowerShell o dau kia. Ba
cho dang ghi nho:

- Giai nen bang `tar.exe` co san trong System32 tu Windows 10 1803 -- doc duoc zip, nen
  khong phai mang theo bo giai nen nao. Package doi toi thieu 10.0.19041 nen chac chan co.
- **Phai nhung manifest `asInvoker`.** Windows doan mot file `.exe` khong co manifest ma
  ten co chu "setup" la trinh cai dat va doi nang quyen -- dung cai duy nhat ca goi nay
  sinh ra de tranh.
- Link `/MT`. Mot trinh cai dat doi cai VC++ redistributable truoc moi chay duoc thi vo
  nghia voi nguoi khong co admin.
- Dang ky bang `PackageManager.RegisterPackageAsync` voi `DeploymentOptions::DevelopmentMode`,
  dung thu ma `Add-AppxPackage -Register` goi ben duoi.

Dieu kien duy nhat: Developer Mode bat.

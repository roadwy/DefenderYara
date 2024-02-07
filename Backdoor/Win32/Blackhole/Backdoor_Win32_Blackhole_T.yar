
rule Backdoor_Win32_Blackhole_T{
	meta:
		description = "Backdoor:Win32/Blackhole.T,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2b 00 0e 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //05 00  FPUMaskValue
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //05 00  ShellExecuteA
		$a_00_3 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //05 00  OpenSCManagerA
		$a_01_4 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //01 00  ShowSuperHidden
		$a_01_5 = {4f 50 45 4e 3d 73 78 73 2e 65 78 65 } //01 00  OPEN=sxs.exe
		$a_01_6 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 73 78 73 2e 65 78 65 } //01 00  shell\open\Command=sxs.exe
		$a_00_7 = {73 65 72 76 69 63 65 73 2e 65 78 65 } //01 00  services.exe
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 2e 64 6c 6c 6c } //01 00  SOFTWARE\Classes\.dlll
		$a_01_9 = {64 6c 6c 6c 5f 61 75 74 6f 5f 66 69 6c 65 } //01 00  dlll_auto_file
		$a_01_10 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 64 6c 31 5f 61 75 74 6f 5f 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  SOFTWARE\Classes\dl1_auto_file\shell\open\command
		$a_01_11 = {73 6f 75 6e 64 6d 61 6e } //01 00  soundman
		$a_01_12 = {73 65 72 76 65 72 2e 65 78 65 } //01 00  server.exe
		$a_01_13 = {57 69 6e 53 74 61 72 2e 64 6c 6c 6c } //00 00  WinStar.dlll
	condition:
		any of ($a_*)
 
}
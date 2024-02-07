
rule TrojanSpy_Win32_Xegumumune_SP_MTB{
	meta:
		description = "TrojanSpy:Win32/Xegumumune.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 08 00 00 03 00 "
		
	strings :
		$a_81_0 = {2a 23 2a 31 37 32 2e 31 36 2e 38 39 2e 32 32 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 2a 23 2a } //03 00  *#*172.16.89.22XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX*#*
		$a_81_1 = {2a 23 2a 61 62 75 32 30 32 30 35 38 35 38 40 67 6d 61 69 6c 2e 63 6f 6d 39 30 30 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2a 23 2a } //02 00  *#*abu20205858@gmail.com900------------------------------------*#*
		$a_81_2 = {75 6e 69 6e 73 74 61 6c 6c 6d 73 66 69 6c 74 65 72 2e 65 78 65 } //02 00  uninstallmsfilter.exe
		$a_81_3 = {75 6e 72 65 67 6d 61 69 6c 2e 62 61 74 } //02 00  unregmail.bat
		$a_81_4 = {69 6d 6f 6e 6c 73 70 69 6e 73 36 34 2e 65 78 65 20 2d 70 20 2d 63 20 62 } //02 00  imonlspins64.exe -p -c b
		$a_81_5 = {69 6e 73 74 61 6c 6c 5f 6c 73 70 2e 65 78 65 20 2d 70 } //02 00  install_lsp.exe -p
		$a_81_6 = {6d 73 66 6c 74 74 72 61 6e 73 2e 65 78 65 20 49 4e 53 54 41 4c 4c 43 41 42 } //02 00  msflttrans.exe INSTALLCAB
		$a_81_7 = {50 72 6f 63 47 75 61 72 64 2e 65 78 65 20 4e 4f 54 52 55 4e 45 58 45 } //00 00  ProcGuard.exe NOTRUNEXE
	condition:
		any of ($a_*)
 
}
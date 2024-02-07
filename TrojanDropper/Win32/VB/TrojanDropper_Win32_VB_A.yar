
rule TrojanDropper_Win32_VB_A{
	meta:
		description = "TrojanDropper:Win32/VB.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 64 00 65 00 6c 00 2e 00 62 00 61 00 74 00 } //01 00  del /f del.bat
		$a_01_1 = {74 00 35 00 38 00 63 00 68 00 61 00 74 00 5f 00 33 00 39 00 38 00 30 00 38 00 35 00 2e 00 65 00 78 00 65 00 } //01 00  t58chat_398085.exe
		$a_01_2 = {31 31 35 62 72 2e 65 78 65 } //01 00  115br.exe
		$a_01_3 = {74 61 6f 2e 69 63 6f } //00 00  tao.ico
	condition:
		any of ($a_*)
 
}
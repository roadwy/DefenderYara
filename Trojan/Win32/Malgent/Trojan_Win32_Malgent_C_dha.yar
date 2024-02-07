
rule Trojan_Win32_Malgent_C_dha{
	meta:
		description = "Trojan:Win32/Malgent.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff d6 8b 45 f4 8a 0c 07 ff 05 90 01 02 00 10 2a cb 80 f1 3f 6a 00 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 90 00 } //01 00 
		$a_00_1 = {74 71 5f 74 65 6c 22 23 27 71 69 69 } //01 00  tq_tel"#'qii
		$a_01_2 = {73 73 4d 55 49 44 4c 4c 2e 64 6c 6c } //01 00  ssMUIDLL.dll
		$a_01_3 = {54 6d 44 62 67 4c 6f 67 2e 64 6c 6c } //00 00  TmDbgLog.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Malgent_C_dha_2{
	meta:
		description = "Trojan:Win32/Malgent.C!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 72 00 72 00 6f 00 72 00 73 00 79 00 73 00 74 00 65 00 6d 00 65 00 } //01 00  raw.githubusercontent.com/errorsysteme
		$a_01_1 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5f 00 43 00 4d 00 2e 00 65 00 78 00 65 00 } //01 00  Install_CM.exe
		$a_01_2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 57 00 4f 00 57 00 36 00 34 00 5c 00 70 00 72 00 6f 00 63 00 65 00 73 00 6c 00 69 00 73 00 74 00 2e 00 74 00 78 00 74 00 } //01 00  C:\Windows\SysWOW64\proceslist.txt
		$a_01_3 = {66 00 6f 00 6e 00 74 00 64 00 72 00 73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  fontdrsvhost.exe
		$a_01_4 = {46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 55 00 49 00 2e 00 65 00 78 00 65 00 } //01 00  FrameworkUI.exe
		$a_01_5 = {6c 00 73 00 61 00 73 00 73 00 5f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 65 00 78 00 65 00 } //01 00  lsass_config.exe
		$a_01_6 = {4c 00 69 00 76 00 65 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 5c 00 53 00 52 00 50 00 6f 00 6c 00 69 00 63 00 79 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //00 00  LiveKernel\SRPolicySvc.exe
	condition:
		any of ($a_*)
 
}
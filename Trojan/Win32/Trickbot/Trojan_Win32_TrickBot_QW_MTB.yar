
rule Trojan_Win32_TrickBot_QW_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {79 69 6d 70 6a 66 64 6c 2e 64 6c 6c } //03 00  yimpjfdl.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //03 00  DllRegisterServer
		$a_81_2 = {61 6b 66 71 71 6a 74 6f 75 79 6f } //03 00  akfqqjtouyo
		$a_81_3 = {61 6c 71 78 64 63 76 66 62 68 6a } //03 00  alqxdcvfbhj
		$a_81_4 = {52 45 6b 6a 75 35 72 6b 77 } //03 00  REkju5rkw
		$a_81_5 = {49 6e 74 65 72 6c 6f 63 6b 65 64 46 6c 75 73 68 53 4c 69 73 74 } //03 00  InterlockedFlushSList
		$a_81_6 = {44 65 63 6f 64 65 50 6f 69 6e 74 65 72 } //00 00  DecodePointer
	condition:
		any of ($a_*)
 
}
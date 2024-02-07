
rule Backdoor_Win32_Berbew_GZ_MTB{
	meta:
		description = "Backdoor:Win32/Berbew.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 c3 31 d8 89 c3 01 d8 89 c3 b8 90 01 04 f7 e3 89 85 90 01 04 89 c3 81 f3 90 01 04 89 d8 29 d8 89 c3 b8 90 01 04 f7 e3 89 85 a4 fe ff ff 89 c3 31 c0 40 5f 5e 5b c9 c2 0c 00 90 00 } //01 00 
		$a_01_1 = {4f 70 65 6e 4d 75 74 65 78 } //00 00  OpenMutex
	condition:
		any of ($a_*)
 
}
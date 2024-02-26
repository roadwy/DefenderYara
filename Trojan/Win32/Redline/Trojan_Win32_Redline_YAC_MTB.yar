
rule Trojan_Win32_Redline_YAC_MTB{
	meta:
		description = "Trojan:Win32/Redline.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 64 a3 00 00 00 00 } //01 00 
		$a_03_1 = {ff d7 80 b6 90 01 05 ff d7 80 86 90 01 05 ff d7 80 b6 90 01 05 ff d7 80 86 90 01 05 ff d7 80 86 90 01 05 ff d7 80 86 90 01 05 46 81 fe 00 76 03 00 0f 82 90 01 04 5f 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
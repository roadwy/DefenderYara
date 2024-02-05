
rule Trojan_Win32_Azorult_GT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 95 a0 fb ff ff 83 c2 01 89 95 a0 fb ff ff 81 bd a0 fb ff ff 90 01 02 00 00 73 2d 8b 85 a0 fb ff ff 33 d2 f7 75 0c 8b 45 08 0f be 0c 10 8b 55 d4 03 95 a0 fb ff ff 0f b6 02 33 c1 8b 4d d4 03 8d a0 fb ff ff 88 01 eb b8 8b 55 d4 90 00 } //01 00 
		$a_00_1 = {56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
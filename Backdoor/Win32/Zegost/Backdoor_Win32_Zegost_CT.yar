
rule Backdoor_Win32_Zegost_CT{
	meta:
		description = "Backdoor:Win32/Zegost.CT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 25 ff ff 00 00 8b 4d 08 03 4d ec 8a 11 32 54 45 f8 8b 45 08 03 45 ec 88 10 66 8b 4d fc 66 83 c1 01 } //01 00 
		$a_01_1 = {00 47 68 30 73 74 } //01 00  䜀と瑳
		$a_01_2 = {00 5f 6b 61 73 70 65 72 73 6b 79 00 } //01 00  开慫灳牥歳y
		$a_01_3 = {00 48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 4e 0d 0a } //00 00 
	condition:
		any of ($a_*)
 
}
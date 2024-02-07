
rule Backdoor_Win32_Glupteba_G_MSR{
	meta:
		description = "Backdoor:Win32/Glupteba.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3b 2d 0b 00 8b 15 04 90 01 03 88 0c 02 c3 90 0a 14 8b 0d b8 90 01 03 8a 8c 01 90 00 } //01 00 
		$a_01_1 = {53 e8 e9 e7 ff ff 83 c3 08 ff 4d fc 75 b1 } //01 00 
		$a_03_2 = {be 14 34 40 00 bf 28 90 01 02 00 a5 a5 a5 66 a5 a4 5f 66 c7 05 29 90 01 02 00 69 72 5e c3 90 00 } //01 00 
		$a_01_3 = {56 65 62 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VebtualProtect
	condition:
		any of ($a_*)
 
}
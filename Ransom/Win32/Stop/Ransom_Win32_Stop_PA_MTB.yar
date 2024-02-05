
rule Ransom_Win32_Stop_PA_MTB{
	meta:
		description = "Ransom:Win32/Stop.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 45 90 01 01 33 c3 33 c6 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //01 00 
		$a_03_1 = {8b de c1 e3 90 01 01 03 5d 90 01 01 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_2 = {88 04 0f 89 75 90 01 01 c1 e8 90 01 01 81 6d 90 01 05 8b 45 90 01 01 a3 90 01 04 8a 45 fe 88 44 0f 01 8a 45 ff 88 44 0f 02 83 c7 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
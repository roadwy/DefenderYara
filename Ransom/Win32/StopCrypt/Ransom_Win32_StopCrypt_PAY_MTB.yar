
rule Ransom_Win32_StopCrypt_PAY_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c3 81 00 47 86 c8 61 c3 } //01 00 
		$a_03_1 = {c2 08 00 81 00 90 01 01 34 ef c6 c3 90 00 } //04 00 
		$a_03_2 = {d3 e8 c7 05 90 01 04 ee 3d ea f4 03 85 90 01 04 33 c3 81 3d 90 01 04 b7 01 90 00 } //04 00 
		$a_03_3 = {d3 eb c7 05 90 01 04 ee 3d ea f4 03 9d 90 01 04 33 da 81 3d 90 01 04 b7 01 90 00 } //04 00 
		$a_03_4 = {d3 e8 c7 05 90 01 04 ee 3d ea f4 03 45 90 02 04 33 c2 89 45 90 01 01 81 fe a3 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
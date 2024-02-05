
rule Ransom_Win32_StopCrypt_SLW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 89 3d 90 01 01 31 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 81 44 24 2c 90 01 04 4b 90 00 } //01 00 
		$a_03_1 = {8b 44 24 18 c1 e8 90 01 01 89 44 24 90 01 01 8b 54 24 90 01 01 01 54 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 83 3d 90 01 04 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
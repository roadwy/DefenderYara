
rule Ransom_Win32_StopCrypt_SLZ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 30 33 4c 24 90 01 01 89 35 90 01 04 31 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 00 } //01 00 
		$a_03_1 = {d3 ea c7 05 90 01 04 ee 3d ea f4 03 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 33 54 24 90 01 01 83 3d 90 01 04 0c 89 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
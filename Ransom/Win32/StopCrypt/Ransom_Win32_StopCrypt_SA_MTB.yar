
rule Ransom_Win32_StopCrypt_SA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 d3 ea 8d 4c 24 90 01 01 89 54 24 90 01 01 8b 54 24 90 01 01 e8 90 01 04 8b 4c 24 90 01 01 33 4c 24 90 01 01 8b 54 24 90 01 01 33 d1 8d 4c 24 90 01 01 89 54 24 90 01 01 89 3d 90 00 } //01 00 
		$a_03_1 = {d3 ee c7 05 90 01 04 ee 3d ea f4 03 74 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 33 74 24 90 01 01 83 3d 90 01 04 0c 89 74 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
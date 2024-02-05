
rule Ransom_Win32_StopCrypt_SLD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 89 35 90 01 04 31 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 00 } //01 00 
		$a_03_1 = {c1 e8 05 89 44 24 90 01 01 8b 54 24 90 01 01 01 54 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 83 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
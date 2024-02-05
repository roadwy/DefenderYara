
rule Ransom_Win32_StopCrypt_PCG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 33 74 24 90 01 01 03 44 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 33 c6 83 3d 90 01 04 0c 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
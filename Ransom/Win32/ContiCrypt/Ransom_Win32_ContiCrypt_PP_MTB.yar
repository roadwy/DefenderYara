
rule Ransom_Win32_ContiCrypt_PP_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 ea 03 8d 04 90 01 01 c1 e0 02 2b f0 0f b6 44 90 01 02 30 90 02 04 8d 04 90 01 01 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
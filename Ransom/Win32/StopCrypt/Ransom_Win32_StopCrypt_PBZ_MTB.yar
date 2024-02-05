
rule Ransom_Win32_StopCrypt_PBZ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 05 03 4d 90 01 01 03 fb 03 c6 33 cf 33 c8 89 45 90 01 01 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 8b 45 90 01 01 29 45 90 01 01 8b 4d 90 01 01 c1 e1 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
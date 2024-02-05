
rule Ransom_Win32_StopCrypt_SLX_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 8b 84 24 90 01 04 8b 8c 24 90 01 04 81 f1 90 01 04 66 90 01 01 3d 45 66 89 84 24 90 01 04 39 4c 24 90 01 01 73 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 8a 54 04 90 01 01 88 54 0c 90 01 01 8b 44 24 90 01 01 83 c0 90 01 01 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
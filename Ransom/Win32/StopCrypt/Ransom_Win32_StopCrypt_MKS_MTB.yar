
rule Ransom_Win32_StopCrypt_MKS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c1 33 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 05 90 01 04 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 c7 89 45 f4 8b 45 90 01 01 03 45 90 01 01 89 45 fc 8b 45 90 01 01 83 0d 90 01 05 c1 e8 90 01 01 c7 05 90 01 08 89 45 0c 8b 45 90 01 01 01 45 0c ff 75 90 01 01 8d 45 f4 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Ransom_Win32_StopCrypt_MKK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b d6 d3 ea 89 45 f0 03 55 dc 33 d0 89 55 ec 8b 45 ec 29 45 f8 25 90 02 04 8b 55 f8 8b c2 8d 4d f0 e8 90 02 04 8b 4d e0 8b c2 c1 e8 90 02 01 89 45 ec 8d 45 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Ransom_Win32_Stopcrypt_YAF_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 01 45 f8 8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 90 01 01 33 d0 31 55 f8 2b 7d f8 89 7d ec 8b 45 e0 29 45 f4 ff 4d e8 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
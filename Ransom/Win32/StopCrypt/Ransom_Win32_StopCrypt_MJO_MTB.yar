
rule Ransom_Win32_StopCrypt_MJO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 8d 4d f8 e8 90 01 04 8b 45 dc 01 45 f8 8b 4d f4 8b 45 f0 81 45 f0 47 86 c8 61 8b d7 d3 ea 03 c7 03 55 e0 33 d0 31 55 f8 8b 45 f8 29 45 ec ff 4d e4 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
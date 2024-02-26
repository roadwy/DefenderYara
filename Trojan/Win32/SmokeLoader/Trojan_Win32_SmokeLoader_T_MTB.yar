
rule Trojan_Win32_SmokeLoader_T_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 8b c2 d3 e8 8b 4d fc 03 c3 33 45 ec 33 c8 8d 45 e8 89 4d fc 2b f1 e8 90 01 04 83 ef 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
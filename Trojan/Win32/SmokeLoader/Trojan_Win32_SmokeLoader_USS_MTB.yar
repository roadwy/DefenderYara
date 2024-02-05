
rule Trojan_Win32_SmokeLoader_USS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.USS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 8d 4d fc e8 90 01 04 8b 45 f8 8b 4d f4 8b 7d d8 8d 14 18 8b c3 d3 e8 8b 4d fc 03 cf 03 45 dc 33 c1 33 c2 29 45 f0 89 45 fc 8b 45 e0 29 45 f8 ff 4d e8 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
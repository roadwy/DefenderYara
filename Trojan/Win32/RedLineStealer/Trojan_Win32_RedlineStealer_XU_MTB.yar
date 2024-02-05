
rule Trojan_Win32_RedlineStealer_XU_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.XU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 33 ca 89 4c 24 90 01 01 89 6c 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 5c 24 90 01 01 81 44 24 90 01 05 ff 4c 24 90 01 01 89 2d 90 01 04 89 5c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
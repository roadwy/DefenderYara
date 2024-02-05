
rule Trojan_Win32_Hancitor_GM_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 44 11 ff 33 c9 a3 90 01 04 89 0d 90 01 04 8b 55 90 01 01 8b 45 90 01 01 8a 08 88 0a 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 8b 4d 90 01 01 81 e9 90 01 04 8b 55 90 01 01 83 da 90 01 01 2b 0d 90 01 04 1b 15 90 01 04 89 0d 90 01 04 89 15 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
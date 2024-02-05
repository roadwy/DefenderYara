
rule Trojan_Win32_SharpPanda_PA_MTB{
	meta:
		description = "Trojan:Win32/SharpPanda.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 8a 04 1f 88 04 1e 88 0c 1f 0f b6 04 1e 8b 4d 90 01 01 03 c2 8b 55 90 01 01 0f b6 c0 8a 04 18 30 04 11 41 89 4d 90 01 01 3b 4d 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
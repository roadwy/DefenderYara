
rule Trojan_Win32_RedlineStealer_XS_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.XS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 75 90 01 01 8a 0c 1a 30 0c 3e 46 3b 75 14 90 01 02 5b 8b c7 5f 5e 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
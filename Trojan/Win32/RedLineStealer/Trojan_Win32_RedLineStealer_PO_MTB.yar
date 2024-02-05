
rule Trojan_Win32_RedLineStealer_PO_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d fc c1 e1 90 01 01 03 4d e8 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc 83 0d 90 01 04 ff 8b c2 c1 e8 90 01 01 03 45 e4 68 90 01 04 33 45 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
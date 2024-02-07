
rule Trojan_Win32_SpyStealer_AZ_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 f7 75 10 8a 0c 1a 30 0c 3e 46 3b 75 14 72 } //01 00 
		$a_01_1 = {75 68 55 49 41 48 73 79 75 74 66 54 57 74 36 37 38 } //00 00  uhUIAHsyutfTWt678
	condition:
		any of ($a_*)
 
}
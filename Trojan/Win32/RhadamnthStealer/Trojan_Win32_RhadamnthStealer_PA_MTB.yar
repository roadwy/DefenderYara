
rule Trojan_Win32_RhadamnthStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/RhadamnthStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2c 01 88 45 90 01 01 8b 45 90 01 01 33 85 90 02 04 0f b6 4d 90 01 01 8b 95 90 02 04 89 04 8a e9 90 00 } //01 00 
		$a_03_1 = {2c 01 88 45 90 01 01 8b 45 90 01 01 8b 8d 90 02 04 d3 e0 0f b6 4d 90 01 01 8b 95 90 02 04 89 04 8a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
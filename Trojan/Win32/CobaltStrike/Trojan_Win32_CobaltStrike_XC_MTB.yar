
rule Trojan_Win32_CobaltStrike_XC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.XC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 0c 3a 83 c7 90 01 01 8b 88 90 01 04 81 c1 90 01 04 03 88 90 01 04 09 88 90 01 04 8b 88 90 01 04 2b 88 90 01 04 31 48 90 01 01 8b 88 90 01 04 01 48 90 01 01 8b 88 90 01 04 81 e9 90 01 04 01 88 90 01 04 8b 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
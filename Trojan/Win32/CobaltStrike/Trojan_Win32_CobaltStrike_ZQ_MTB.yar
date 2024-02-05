
rule Trojan_Win32_CobaltStrike_ZQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 04 32 83 c6 90 01 01 8b 41 90 01 01 83 f0 90 01 01 29 81 90 01 04 8b 81 90 01 04 83 f0 90 01 01 0f af 41 90 01 01 89 41 90 01 01 8b 81 90 01 04 01 41 90 01 01 81 fe 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
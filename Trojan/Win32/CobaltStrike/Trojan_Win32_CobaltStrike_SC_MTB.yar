
rule Trojan_Win32_CobaltStrike_SC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 0c 02 ff 46 90 01 01 8b 86 90 01 04 83 e8 90 01 01 31 86 90 01 04 8b 46 90 01 01 83 e8 90 01 01 31 46 90 01 01 8b 46 90 01 01 8b 8e 90 01 04 88 1c 01 8b 46 90 01 01 ff 46 90 01 01 2d 90 01 04 01 86 90 01 04 8b 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_CobaltStrike_HO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 90 01 01 81 7d 90 01 05 73 90 01 01 8b 45 90 01 01 03 45 90 01 01 0f b6 08 8b 55 90 01 01 03 55 90 01 01 0f b6 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
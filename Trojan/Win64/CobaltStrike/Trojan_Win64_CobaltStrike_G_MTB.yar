
rule Trojan_Win64_CobaltStrike_G_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8b 05 06 1e 00 00 39 c2 73 90 01 01 8b 45 fc 48 98 48 8d 15 76 1a 00 00 0f b6 04 10 83 f0 90 01 01 89 c1 8b 45 fc 48 98 48 8d 15 61 1a 00 00 88 0c 10 83 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
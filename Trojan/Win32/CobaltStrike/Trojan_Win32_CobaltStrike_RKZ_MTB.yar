
rule Trojan_Win32_CobaltStrike_RKZ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 ff 76 20 6a 00 ff 15 } //01 00 
		$a_03_1 = {31 46 18 8b 86 c0 00 00 00 35 90 01 04 29 86 f4 00 00 00 8b 86 d4 00 00 00 83 f0 90 01 01 0f af 46 1c 89 46 1c 8b 86 94 00 00 00 09 86 d4 00 00 00 81 ff 90 01 02 00 00 0f 8c f0 fe ff ff 90 00 } //01 00 
		$a_03_2 = {01 46 7c 8b 4e 5c 8b 86 b4 00 00 00 8b d3 c1 ea 90 01 01 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
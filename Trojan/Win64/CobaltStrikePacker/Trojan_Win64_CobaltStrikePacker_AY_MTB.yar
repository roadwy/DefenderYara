
rule Trojan_Win64_CobaltStrikePacker_AY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikePacker.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff c9 31 88 90 01 04 48 8b 88 90 01 04 46 8b 04 09 49 83 c1 04 44 0f af 40 90 01 01 8b 48 90 01 01 2b 88 90 01 04 81 c1 90 01 04 01 48 90 01 01 48 63 50 90 01 01 48 8b 88 90 01 04 44 88 04 0a ff 40 90 01 01 8b 90 90 90 01 04 8b 88 90 01 04 83 ea 90 01 01 44 8b 80 90 01 04 0f af ca 89 88 90 01 04 8b 50 90 01 01 83 c2 90 01 01 41 03 d0 01 50 90 01 01 44 33 40 90 01 01 44 01 80 90 01 04 8b 48 90 01 01 2b 48 90 01 01 81 f1 90 01 04 01 88 90 01 04 49 81 f9 90 01 04 90 13 8b 88 90 00 } //01 00 
		$a_03_1 = {88 14 01 41 8b d0 ff 83 90 01 04 48 63 8b 90 01 04 48 8b 83 90 01 04 c1 ea 08 88 14 01 ff 83 90 01 04 8b 83 90 01 04 2b 43 90 01 01 2d 90 01 04 01 43 90 01 01 48 63 93 90 01 04 48 8b 8b 90 01 04 44 88 04 0a ff 83 90 01 04 8b 4b 90 01 01 81 f1 90 01 04 29 4b 90 01 01 49 81 f9 90 01 04 90 13 8b 4b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
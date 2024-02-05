
rule Trojan_Win64_CobaltStrike_FSS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 c8 89 0d f5 24 02 00 48 63 4b 6c 48 8b 83 90 01 04 88 14 01 41 8b d0 ff 43 6c 48 8b 0d 9e 24 02 00 8b 05 a8 24 02 00 c1 ea 08 31 41 2c 8b 05 30 25 02 00 8b 4b 28 05 aa 12 f4 ff 03 c8 48 8b 05 4b 25 02 00 89 0d 19 25 02 00 48 63 0d ea 24 02 00 88 14 01 ff 05 e1 24 02 00 48 8b 05 5e 24 02 00 8b 88 90 01 04 03 4b 48 81 f1 97 60 13 00 29 4b 28 8b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
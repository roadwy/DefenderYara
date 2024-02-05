
rule Trojan_Win64_CobaltStrike_PCF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PCF!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 4a 40 f3 0f 6f 52 50 f3 0f 6f 5a 60 f3 0f 6f 62 70 66 0f 7f 49 40 66 0f 7f 51 50 66 0f 7f 59 60 66 0f 7f 61 70 48 81 c1 80 00 00 00 48 81 c2 80 00 00 00 49 81 e8 80 00 00 00 49 81 f8 80 00 00 00 73 94 4d 8d 48 0f 49 83 e1 f0 4d 8b d9 49 c1 eb 04 47 8b 9c 9a 28 45 00 00 4d 03 da 41 ff e3 } //04 00 
		$a_01_1 = {48 8d 44 24 48 48 89 44 24 20 45 33 c9 45 33 c0 ba 0c 80 00 00 48 8b 4c 24 40 ff 54 24 60 } //02 00 
		$a_01_2 = {53 75 70 33 72 53 33 63 75 72 33 50 34 73 73 21 31 } //00 00 
	condition:
		any of ($a_*)
 
}
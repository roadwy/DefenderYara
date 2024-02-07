
rule Trojan_Win64_CobaltStrike_SMW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SMW!MTB,SIGNATURE_TYPE_PEHSTR,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 0a f3 0f 6f 52 10 f3 0f 6f 5a 20 f3 0f 6f 62 30 66 0f 7f 09 66 0f 7f 51 10 66 0f 7f 59 20 66 0f 7f 61 30 f3 0f 6f 4a 40 f3 0f 6f 52 50 f3 0f 6f 5a 60 f3 0f 6f 62 70 66 0f 7f 49 40 66 0f 7f 51 50 66 0f 7f 59 60 66 0f 7f 61 70 48 81 c1 80 00 00 00 48 81 c2 80 00 00 00 49 81 e8 80 00 00 00 49 81 f8 80 00 00 00 73 94 } //0a 00 
		$a_01_1 = {45 33 c9 44 8b c0 48 8b 94 24 c0 00 00 00 48 8b 4c 24 48 ff 54 24 68 85 c0 75 07 } //01 00 
		$a_01_2 = {50 61 73 73 77 30 72 64 21 } //00 00  Passw0rd!
	condition:
		any of ($a_*)
 
}
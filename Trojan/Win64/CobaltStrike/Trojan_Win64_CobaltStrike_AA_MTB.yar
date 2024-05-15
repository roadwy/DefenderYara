
rule Trojan_Win64_CobaltStrike_AA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 d0 8b c5 ff c5 6b d2 90 01 01 2b c2 48 63 c8 48 8b 44 24 90 02 02 42 0f b6 8c 39 90 01 04 41 32 4c 00 ff 41 88 4c 18 ff 3b 6c 24 90 01 01 72 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AA_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00  Go build ID:
		$a_01_1 = {55 44 52 62 6f 74 54 4f 4d 74 6b 75 66 37 54 54 4a 51 50 69 53 56 6a 64 52 5a 71 55 6d 69 31 6f 47 65 35 66 55 73 32 68 4c 77 77 3d } //01 00  UDRbotTOMtkuf7TTJQPiSVjdRZqUmi1oGe5fUs2hLww=
		$a_01_2 = {65 47 37 52 58 5a 48 64 71 4f 4a 31 69 2b 30 6c 67 4c 67 43 70 53 58 41 70 36 4d 33 4c 59 6c 41 6f 36 6f 73 67 53 69 30 78 4f 4d 3d } //00 00  eG7RXZHdqOJ1i+0lgLgCpSXAp6M3LYlAo6osgSi0xOM=
	condition:
		any of ($a_*)
 
}
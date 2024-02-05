
rule Trojan_Win64_TurtleLoader_CS_dha{
	meta:
		description = "Trojan:Win64/TurtleLoader.CS!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 75 72 8b 80 88 00 00 00 48 85 c0 74 67 48 01 d0 50 8b } //01 00 
		$a_01_1 = {d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 } //01 00 
		$a_01_2 = {24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}
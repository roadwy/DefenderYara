
rule Trojan_Win32_Reder_A{
	meta:
		description = "Trojan:Win32/Reder.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 0b 00 00 06 00 "
		
	strings :
		$a_01_0 = {7e 0e 8a 04 32 88 04 31 83 c2 03 41 3b d7 7c f2 } //01 00 
		$a_01_1 = {79 68 65 75 6a 78 62 76 65 6f 70 } //01 00  yheujxbveop
		$a_01_2 = {69 6e 69 2e 73 65 6c 69 66 6f 72 70 00 } //01 00 
		$a_01_3 = {63 64 61 6d 66 72 64 74 67 } //01 00  cdamfrdtg
		$a_01_4 = {55 73 64 44 70 70 50 66 52 00 } //01 00  獕䑤灰晐R
		$a_01_5 = {50 7a 7a 41 76 66 53 62 67 53 74 74 00 } //01 00 
		$a_01_6 = {65 6a 6f 65 6a 6f 6e 73 78 21 33 32 00 } //01 00 
		$a_01_7 = {21 72 65 64 65 72 21 00 } //01 00  爡摥牥!
		$a_01_8 = {21 63 6f 6e 74 65 6e 74 21 00 } //01 00  挡湯整瑮!
		$a_01_9 = {21 73 74 6f 72 61 67 65 21 00 } //01 00  猡潴慲敧!
		$a_01_10 = {21 6b 69 6c 6c 21 00 } //00 00 
	condition:
		any of ($a_*)
 
}
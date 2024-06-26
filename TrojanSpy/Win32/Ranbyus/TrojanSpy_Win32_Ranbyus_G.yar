
rule TrojanSpy_Win32_Ranbyus_G{
	meta:
		description = "TrojanSpy:Win32/Ranbyus.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 7d 0c 04 75 30 81 7d fc 69 42 4b 53 75 27 } //02 00 
		$a_01_1 = {81 7d fc 93 4f 23 9a } //02 00 
		$a_03_2 = {ff 93 00 04 00 00 ff 76 50 8d 85 90 01 04 ff 76 48 50 e8 90 00 } //02 00 
		$a_03_3 = {6a 02 6a 0a 8d 90 01 01 60 90 01 01 57 ff 90 01 05 8a 45 63 3c 01 74 0d 3c 03 74 09 90 00 } //01 00 
		$a_01_4 = {8b 55 0c 0f b6 14 17 c1 e1 08 0b ca 47 3b 7d 10 75 02 33 ff 4b 75 e9 31 08 83 c0 04 ff 4d 08 } //01 00 
		$a_01_5 = {2e 69 42 61 6e 6b 2a } //01 00  .iBank*
		$a_01_6 = {62 6f 74 6e 65 74 31 } //01 00  botnet1
		$a_01_7 = {42 53 52 5f 41 4e 59 43 52 4c 46 29 } //01 00  BSR_ANYCRLF)
		$a_01_8 = {25 73 3f 69 64 3d 25 73 26 73 65 73 73 69 6f 6e 3d 25 75 26 76 3d 25 75 } //00 00  %s?id=%s&session=%u&v=%u
	condition:
		any of ($a_*)
 
}
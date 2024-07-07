
rule Trojan_Win32_TrickBotCrypt_FT_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 41 08 8b 51 28 0b c7 85 d2 75 90 01 01 83 c8 04 6a 00 50 e8 90 01 04 0f b6 4c 24 90 01 01 8b 15 90 01 04 8a 14 11 8b 44 24 90 01 01 8b 4c 24 90 01 01 30 14 08 8b 4c 24 90 01 01 40 3b c1 89 44 24 90 00 } //5
		$a_81_1 = {65 24 23 4f 40 72 6b 35 30 33 62 30 68 40 79 71 5f 7a 36 71 6d 4d 63 24 79 3f 75 51 4d 24 3f 38 72 40 52 34 52 37 66 39 54 4a 76 35 78 39 35 36 52 71 78 46 75 23 } //5 e$#O@rk503b0h@yq_z6qmMc$y?uQM$?8r@R4R7f9TJv5x956RqxFu#
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*5) >=5
 
}

rule Trojan_BAT_Seraph_ZY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 63 72 79 70 74 65 64 2e 65 78 65 } //01 00  _crypted.exe
		$a_01_1 = {7a 45 6b 6b 66 74 4c 75 45 79 54 6e 6d 6d 73 50 68 46 6f 51 67 66 74 58 50 4e 79 72 } //01 00  zEkkftLuEyTnmmsPhFoQgftXPNyr
		$a_01_2 = {78 46 4e 57 57 4b 54 49 56 73 76 7a 62 6e 73 4f 6e 4d 6f 50 55 75 41 49 62 } //01 00  xFNWWKTIVsvzbnsOnMoPUuAIb
		$a_01_3 = {77 4d 75 6f 52 67 57 79 44 78 4f 72 6f 63 74 71 77 73 7a 7a 57 66 69 4f 55 53 47 } //01 00  wMuoRgWyDxOroctqwszzWfiOUSG
		$a_01_4 = {4a 68 56 49 42 68 41 51 6f 67 63 73 75 56 55 4d 42 64 71 76 66 62 77 6f 48 } //01 00  JhVIBhAQogcsuVUMBdqvfbwoH
		$a_01_5 = {56 67 62 4b 79 72 68 4c 42 59 5a 4e 6d 51 57 68 4a 72 5a 63 72 78 62 44 41 79 6b } //01 00  VgbKyrhLBYZNmQWhJrZcrxbDAyk
		$a_01_6 = {44 65 62 75 67 67 65 72 } //01 00  Debugger
		$a_01_7 = {64 35 38 65 30 38 63 64 2d 33 62 39 62 2d 34 65 39 62 2d 62 30 34 61 2d 32 63 39 65 66 38 66 61 61 62 37 35 } //00 00  d58e08cd-3b9b-4e9b-b04a-2c9ef8faab75
	condition:
		any of ($a_*)
 
}
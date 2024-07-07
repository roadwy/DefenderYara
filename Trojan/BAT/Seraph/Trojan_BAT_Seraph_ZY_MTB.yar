
rule Trojan_BAT_Seraph_ZY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {5f 63 72 79 70 74 65 64 2e 65 78 65 } //1 _crypted.exe
		$a_01_1 = {7a 45 6b 6b 66 74 4c 75 45 79 54 6e 6d 6d 73 50 68 46 6f 51 67 66 74 58 50 4e 79 72 } //1 zEkkftLuEyTnmmsPhFoQgftXPNyr
		$a_01_2 = {78 46 4e 57 57 4b 54 49 56 73 76 7a 62 6e 73 4f 6e 4d 6f 50 55 75 41 49 62 } //1 xFNWWKTIVsvzbnsOnMoPUuAIb
		$a_01_3 = {77 4d 75 6f 52 67 57 79 44 78 4f 72 6f 63 74 71 77 73 7a 7a 57 66 69 4f 55 53 47 } //1 wMuoRgWyDxOroctqwszzWfiOUSG
		$a_01_4 = {4a 68 56 49 42 68 41 51 6f 67 63 73 75 56 55 4d 42 64 71 76 66 62 77 6f 48 } //1 JhVIBhAQogcsuVUMBdqvfbwoH
		$a_01_5 = {56 67 62 4b 79 72 68 4c 42 59 5a 4e 6d 51 57 68 4a 72 5a 63 72 78 62 44 41 79 6b } //1 VgbKyrhLBYZNmQWhJrZcrxbDAyk
		$a_01_6 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_7 = {64 35 38 65 30 38 63 64 2d 33 62 39 62 2d 34 65 39 62 2d 62 30 34 61 2d 32 63 39 65 66 38 66 61 61 62 37 35 } //1 d58e08cd-3b9b-4e9b-b04a-2c9ef8faab75
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
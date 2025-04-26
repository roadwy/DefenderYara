
rule Trojan_Win64_AtlasClipper_A_MTB{
	meta:
		description = "Trojan:Win64/AtlasClipper.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 65 78 70 2e 28 2a 52 65 67 65 78 70 29 2e 4d 61 74 63 68 53 74 72 69 6e 67 } //2 regexp.(*Regexp).MatchString
		$a_01_1 = {72 65 67 65 78 70 2e 28 2a 52 65 67 65 78 70 29 2e 64 6f 4d 61 74 63 68 } //2 regexp.(*Regexp).doMatch
		$a_01_2 = {44 7b 31 7d 5b 35 2d 39 41 2d 48 4a 2d 4e 50 2d 55 5d 7b 31 7d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 33 32 7d } //2 D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}
		$a_01_3 = {28 5e 7c 5c 57 29 28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 33 39 7d 28 24 7c 5c 57 29 } //2 (^|\W)(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}($|\W)
		$a_01_4 = {77 69 6e 64 6f 77 73 2e 43 72 65 61 74 65 4d 75 74 65 78 } //2 windows.CreateMutex
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}
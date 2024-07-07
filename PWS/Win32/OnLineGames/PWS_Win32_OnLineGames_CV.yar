
rule PWS_Win32_OnLineGames_CV{
	meta:
		description = "PWS:Win32/OnLineGames.CV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 61 73 74 47 61 6d 65 53 65 72 76 65 72 00 00 75 73 65 72 5c 75 69 63 6f 6d 6d 6f 6e 2e 69 6e 69 } //1
		$a_03_1 = {6a 05 52 68 d2 60 47 00 6a 00 e8 90 01 02 ff ff 68 90 01 02 00 10 8d 90 01 03 6a 06 50 68 9b e6 40 00 6a 01 e8 90 01 02 ff ff 90 00 } //1
		$a_03_2 = {c6 06 e9 55 55 8d 83 90 01 04 57 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02 c1 ea 10 c1 e8 18 88 56 03 56 88 46 04 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
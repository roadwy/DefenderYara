
rule Trojan_Win64_CobaltStrike_CCAT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 39 6e 76 66 47 79 53 72 47 4c 56 6e 6b 34 6f 62 54 74 35 32 62 45 59 67 68 59 6a 31 38 4c 74 } //01 00  F9nvfGySrGLVnk4obTt52bEYghYj18Lt
		$a_01_1 = {4a 54 54 56 5a 33 2b 37 64 35 42 73 63 69 71 44 70 30 6d 78 67 58 55 46 58 65 2b 64 73 62 50 37 } //01 00  JTTVZ3+7d5BsciqDp0mxgXUFXe+dsbP7
		$a_01_2 = {49 42 6f 78 38 50 47 4a 64 4e 74 70 71 4d 4f 48 73 57 64 2b 46 52 77 74 72 4e 32 4a 41 46 37 73 } //00 00  IBox8PGJdNtpqMOHsWd+FRwtrN2JAF7s
	condition:
		any of ($a_*)
 
}
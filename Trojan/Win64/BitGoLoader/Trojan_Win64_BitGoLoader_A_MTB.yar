
rule Trojan_Win64_BitGoLoader_A_MTB{
	meta:
		description = "Trojan:Win64/BitGoLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {20 47 6f 20 62 75 69 6c 64 20 49 44 3a } //1  Go build ID:
		$a_81_1 = {6d 61 69 6e 2e 52 65 64 69 72 65 63 74 54 6f 50 61 79 6c 6f 61 64 } //1 main.RedirectToPayload
		$a_81_2 = {6d 61 69 6e 2e 48 6f 6c 6c 6f 77 50 72 6f 63 65 73 73 } //1 main.HollowProcess
		$a_81_3 = {6d 61 69 6e 2e 41 65 73 44 65 63 6f 64 65 2e 66 75 6e 63 31 } //1 main.AesDecode.func1
		$a_81_4 = {6d 61 69 6e 2e 5f 52 75 6e 50 45 } //1 main._RunPE
		$a_81_5 = {68 31 3a 36 6f 4e 42 6c 53 64 69 31 51 71 4d 31 50 4e 57 37 46 50 41 36 78 4f 47 41 35 55 4e 73 58 6e 6b 61 59 5a 7a 39 76 64 50 47 68 41 3d } //1 h1:6oNBlSdi1QqM1PNW7FPA6xOGA5UNsXnkaYZz9vdPGhA=
		$a_81_6 = {68 31 3a 55 51 48 4d 67 4c 4f 2b 54 78 4f 45 6c 78 35 42 35 48 5a 34 68 4a 51 73 6f 4a 2f 50 76 55 76 4b 52 68 4a 48 44 51 58 4f 38 50 38 3d } //1 h1:UQHMgLO+TxOElx5B5HZ4hJQsoJ/PvUvKRhJHDQXO8P8=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}
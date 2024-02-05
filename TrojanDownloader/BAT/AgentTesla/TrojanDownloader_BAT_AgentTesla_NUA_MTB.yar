
rule TrojanDownloader_BAT_AgentTesla_NUA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 } //01 00 
		$a_80_1 = {45 72 6a 6d 6d 78 68 7a 6e 6d 61 64 6b 6b 78 7a 6c 70 69 6d 72 65 6c } //Erjmmxhznmadkkxzlpimrel  01 00 
		$a_80_2 = {47 64 65 69 64 6e 7a 76 6c 67 6e 64 6b 61 63 73 70 73 70 73 6b 70 77 2e 55 75 63 76 6a 69 65 67 77 6e 64 } //Gdeidnzvlgndkacspspskpw.Uucvjiegwnd  01 00 
		$a_80_3 = {56 73 6e 69 73 68 76 77 75 61 65 69 71 62 69 76 2e 46 6b 6b 69 76 73 72 77 6c 71 6a 6d 76 6d 6b 77 68 65 68 72 } //Vsnishvwuaeiqbiv.Fkkivsrwlqjmvmkwhehr  01 00 
		$a_80_4 = {4d 69 79 66 6b 79 61 67 67 6d 67 74 2e 43 76 64 67 65 7a 6e 70 62 } //Miyfkyaggmgt.Cvdgeznpb  01 00 
		$a_80_5 = {54 75 6f 64 71 6a 6b 6a 6b 6d 76 69 70 61 73 71 76 64 72 64 6b 74 66 6d 2e 46 67 75 63 65 76 6a 75 71 6e 63 79 71 6b 63 } //Tuodqjkjkmvipasqvdrdktfm.Fgucevjuqncyqkc  01 00 
		$a_80_6 = {4e 62 77 6f 6d 67 68 6c 74 77 68 79 76 6b 6b 6e 6e 6c 77 76 2e 4f 76 6b 72 74 64 72 70 77 74 65 75 6e 64 61 } //Nbwomghltwhyvkknnlwv.Ovkrtdrpwteunda  00 00 
	condition:
		any of ($a_*)
 
}
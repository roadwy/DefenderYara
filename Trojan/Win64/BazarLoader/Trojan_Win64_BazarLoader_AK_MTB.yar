
rule Trojan_Win64_BazarLoader_AK_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6e 41 56 63 72 41 62 4b 6c 4d 4e 69 2e 70 64 62 } //nAVcrAbKlMNi.pdb  3
		$a_80_1 = {43 4c 55 56 47 48 63 5a 47 7a 63 4e 71 44 45 52 47 62 67 70 71 4c 67 } //CLUVGHcZGzcNqDERGbgpqLg  3
		$a_80_2 = {46 47 6e 6b 4a 71 4c 49 56 79 44 63 4a 6d 72 6b 42 53 48 55 4e 6d 4c 67 46 6d 44 63 } //FGnkJqLIVyDcJmrkBSHUNmLgFmDc  3
		$a_80_3 = {53 74 61 72 74 53 65 72 76 65 72 } //StartServer  3
		$a_80_4 = {53 74 61 72 74 57 } //StartW  3
		$a_80_5 = {53 74 6f 70 53 65 72 76 65 72 } //StopServer  3
		$a_80_6 = {55 6e 72 65 67 69 73 74 65 72 41 70 70 6c 69 63 61 74 69 6f 6e 52 65 63 6f 76 65 72 79 43 61 6c 6c 62 61 63 6b } //UnregisterApplicationRecoveryCallback  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
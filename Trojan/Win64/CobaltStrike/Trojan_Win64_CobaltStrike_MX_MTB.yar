
rule Trojan_Win64_CobaltStrike_MX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 41 46 59 68 76 62 54 7a 56 63 6b 6f 78 63 50 52 } //2 AAFYhvbTzVckoxcPR
		$a_01_1 = {41 42 56 62 6f 4c 78 69 6c 5a 63 49 49 4e 4a 56 44 } //2 ABVboLxilZcIINJVD
		$a_01_2 = {41 42 58 77 57 72 43 4a 55 68 52 50 6d 49 67 4f } //2 ABXwWrCJUhRPmIgO
		$a_01_3 = {41 42 63 71 6a 77 56 65 53 7a 43 65 55 43 } //2 ABcqjwVeSzCeUC
		$a_01_4 = {41 42 78 44 61 64 4e 74 72 55 6f 4d 59 67 } //2 ABxDadNtrUoMYg
		$a_01_5 = {41 43 48 76 4a 4b 46 58 51 49 58 71 74 53 62 51 64 58 62 4a 49 74 } //2 ACHvJKFXQIXqtSbQdXbJIt
		$a_01_6 = {41 43 4d 41 47 6c 53 6f 44 51 47 6e 5a 49 54 41 76 49 69 4c } //2 ACMAGlSoDQGnZITAvIiL
		$a_01_7 = {42 4a 6d 71 4b 50 58 6e 6c 4e 6d 4e 75 4a 69 59 51 } //2 BJmqKPXnlNmNuJiYQ
		$a_01_8 = {42 4c 54 4c 61 4c 46 57 6f 45 6d 44 6b 73 72 48 4e 52 46 72 78 43 61 6d 54 } //2 BLTLaLFWoEmDksrHNRFrxCamT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=18
 
}

rule Trojan_Win32_Revil_SG_MTB{
	meta:
		description = "Trojan:Win32/Revil.SG!MTB!!Revil.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,16 00 16 00 08 00 00 0a 00 "
		
	strings :
		$a_81_0 = {22 6e 6e 61 6d 65 22 3a 22 7b 45 58 54 7d 2d 72 65 61 64 6d 65 2e 74 78 74 22 } //0a 00  "nname":"{EXT}-readme.txt"
		$a_81_1 = {51 51 42 73 41 47 77 41 49 41 42 76 41 47 59 41 49 41 42 35 41 47 38 41 64 51 42 79 41 43 41 41 5a 67 42 70 41 47 77 41 5a 51 42 7a 41 43 41 41 59 51 42 79 41 47 55 41 49 41 42 6c 41 47 34 41 59 77 42 79 41 48 6b 41 63 41 42 30 41 47 55 41 5a 41 41 68 41 41 30 } //01 00  QQBsAGwAIABvAGYAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAhAA0
		$a_81_2 = {22 73 76 63 22 3a 5b 22 } //01 00  "svc":["
		$a_81_3 = {22 6e 62 6f 64 79 22 3a 22 } //01 00  "nbody":"
		$a_81_4 = {22 77 69 70 65 22 3a } //01 00  "wipe":
		$a_81_5 = {22 77 66 6c 64 22 3a 5b } //01 00  "wfld":[
		$a_81_6 = {22 70 72 63 22 3a } //01 00  "prc":
		$a_81_7 = {22 64 6d 6e 22 3a } //00 00  "dmn":
	condition:
		any of ($a_*)
 
}
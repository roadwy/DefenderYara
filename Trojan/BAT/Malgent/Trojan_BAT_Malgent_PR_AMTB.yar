
rule Trojan_BAT_Malgent_PR_AMTB{
	meta:
		description = "Trojan:BAT/Malgent.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {45 3a 5c 50 52 4f 4a 45 54 4f 53 32 30 32 33 5c 43 53 48 41 52 50 5c 52 41 54 5c 4d 58 4e 4f 42 55 47 4d 41 47 5c 42 69 6e 5c 52 65 6c 65 61 73 65 5c 6d 73 65 64 67 65 5f 65 6c 66 2e 70 64 62 } //1 E:\PROJETOS2023\CSHARP\RAT\MXNOBUGMAG\Bin\Release\msedge_elf.pdb
		$a_81_1 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_81_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_4 = {4b 41 53 6a 44 51 41 37 46 63 4f 54 6c 6a 6d 43 30 50 56 42 55 4a 6e 42 4e 42 37 63 62 75 72 72 56 43 4b 33 64 66 30 66 73 64 6b 3d } //1 KASjDQA7FcOTljmC0PVBUJnBNB7cburrVCK3df0fsdk=
		$a_81_5 = {73 43 36 7a 70 36 70 30 75 69 32 51 7a 46 48 4b 63 66 71 36 76 59 6c 36 43 5a 33 55 32 56 6f 37 79 57 31 4c 67 4b 46 54 4a 36 51 3d } //1 sC6zp6p0ui2QzFHKcfq6vYl6CZ3U2Vo7yW1LgKFTJ6Q=
		$a_81_6 = {6c 36 50 6a 50 6b 75 32 57 30 4e 61 68 43 62 64 33 36 48 52 72 4d 74 33 4f 76 6a 59 33 73 76 77 31 6c 31 56 41 72 36 33 37 39 35 5a 53 75 76 6f 6c 69 59 72 54 37 36 6a 68 62 54 72 34 44 45 38 } //1 l6PjPku2W0NahCbd36HRrMt3OvjY3svw1l1VAr63795ZSuvoliYrT76jhbTr4DE8
		$a_81_7 = {6f 32 79 64 4c 77 47 69 36 68 49 73 48 72 6f 46 43 64 53 69 52 63 52 48 59 74 5a 6e 76 62 30 76 43 77 76 53 58 } //1 o2ydLwGi6hIsHroFCdSiRcRHYtZnvb0vCwvSX
		$a_81_8 = {67 5a 5a 6d 30 58 72 59 64 79 49 52 69 68 6e 48 30 67 6f 6c 67 54 6e 77 3d 3d } //1 gZZm0XrYdyIRihnH0golgTnw==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule Trojan_BAT_Malgent_PR_AMTB_2{
	meta:
		description = "Trojan:BAT/Malgent.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_1 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {45 3a 5c 50 52 4f 4a 45 54 4f 53 32 30 32 33 5c 43 53 48 41 52 50 5c 52 41 54 5c 4d 58 4e 4f 42 55 47 4d 41 47 5c 42 69 6e 5c 52 65 6c 65 61 73 65 5c 56 43 52 55 4e 54 49 4d 45 31 34 30 2e 70 64 62 } //1 E:\PROJETOS2023\CSHARP\RAT\MXNOBUGMAG\Bin\Release\VCRUNTIME140.pdb
		$a_81_4 = {6f 32 79 64 4c 77 47 69 36 68 49 73 48 72 6f 46 43 64 53 69 52 63 52 48 59 74 5a 6e 76 62 30 76 43 77 76 53 58 } //1 o2ydLwGi6hIsHroFCdSiRcRHYtZnvb0vCwvSX
		$a_81_5 = {67 5a 5a 6d 30 58 72 59 64 79 49 52 69 68 6e 48 30 67 6f 6c 67 54 6e 77 3d 3d } //1 gZZm0XrYdyIRihnH0golgTnw==
		$a_81_6 = {4b 41 53 6a 44 51 41 37 46 63 4f 54 6c 6a 6d 43 30 50 56 42 55 4a 6e 42 4e 42 37 63 62 75 72 72 56 43 4b 33 64 66 30 66 73 64 6b 3d } //1 KASjDQA7FcOTljmC0PVBUJnBNB7cburrVCK3df0fsdk=
		$a_81_7 = {73 43 36 7a 70 36 70 30 75 69 32 51 7a 46 48 4b 63 66 71 36 76 59 6c 36 43 5a 33 55 32 56 6f 37 79 57 31 4c 67 4b 46 54 4a 36 51 3d } //1 sC6zp6p0ui2QzFHKcfq6vYl6CZ3U2Vo7yW1LgKFTJ6Q=
		$a_81_8 = {6c 36 50 6a 50 6b 75 32 57 30 4e 61 68 43 62 64 33 36 48 52 72 4d 74 33 4f 76 6a 59 33 73 76 77 31 6c 31 56 41 72 36 33 37 39 35 5a 53 75 76 6f 6c 69 59 72 54 37 36 6a 68 62 54 72 34 44 45 38 } //1 l6PjPku2W0NahCbd36HRrMt3OvjY3svw1l1VAr63795ZSuvoliYrT76jhbTr4DE8
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
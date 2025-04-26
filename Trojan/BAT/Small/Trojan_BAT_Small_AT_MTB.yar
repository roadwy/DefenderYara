
rule Trojan_BAT_Small_AT_MTB{
	meta:
		description = "Trojan:BAT/Small.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {0a 72 1b 03 19 70 02 7b 01 ?? ?? 04 72 1f 03 19 70 28 ?? ?? ?? 0a 28 1a ?? ?? 0a 26 2a 86 28 12 ?? ?? 0a 72 1b 03 19 70 02 7b 02 ?? ?? 04 72 1f 03 19 70 28 13 ?? ?? 0a 28 1a ?? ?? 0a 26 2a } //10
		$a_80_1 = {48 34 73 49 41 41 41 41 41 41 41 45 41 4f 30 35 32 33 62 69 75 4c 49 66 6c 49 65 59 32 33 52 34 32 41 38 6c 33 37 44 42 42 42 6c 38 66 63 4d 32 45 57 42 7a 36 51 41 78 35 75 74 33 6c 57 77 43 70 4e 4f 7a 7a 75 79 7a 7a 6a 72 37 6f 62 56 6d 55 6b 69 75 65 35 57 6b 4b 76 58 4d } //H4sIAAAAAAAEAO0523biuLIflIeY23R42A8l37DBBBl8fcM2EWBz6QAx5ut3lWwCpNOzzuyzzjr7obVmUkiue5WkKvXM  5
		$a_00_2 = {63 66 6b 62 d8 b1 d9 82 d9 8a d8 ae 75 76 67 75 6a d8 af d9 85 d8 b1 d8 b9 } //5
		$a_00_3 = {69 d9 88 74 62 65 6c 79 67 70 73 d9 84 } //5
		$a_80_4 = {47 65 74 54 65 6d 70 50 61 74 68 } //GetTempPath  3
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=21
 
}
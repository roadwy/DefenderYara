
rule Trojan_Win64_Dridex_ME_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 70 52 36 7c 4d 4a 2e 70 64 62 } //ppR6|MJ.pdb  3
		$a_80_1 = {48 77 42 76 4b 77 61 73 47 62 69 74 63 68 65 73 5a 50 } //HwBvKwasGbitchesZP  3
		$a_80_2 = {6f 49 6e 45 43 61 6e 61 72 79 79 69 74 43 68 72 6f 6d 65 } //oInECanaryyitChrome  3
		$a_80_3 = {62 61 72 62 65 74 61 29 2c 62 79 72 6f 75 67 68 6c 79 } //barbeta),byroughly  3
		$a_80_4 = {52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 } //RemoveDirectoryA  3
		$a_80_5 = {47 65 74 54 69 6d 65 46 6f 72 6d 61 74 57 } //GetTimeFormatW  3
		$a_80_6 = {50 61 74 68 52 65 6d 6f 76 65 41 72 67 73 57 } //PathRemoveArgsW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
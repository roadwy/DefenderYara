
rule Ransom_Win32_Snatch_MA_MTB{
	meta:
		description = "Ransom:Win32/Snatch.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin delete shadows /All /Quiet
		$a_01_1 = {64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 20 71 75 69 65 74 } //1 delete catalog - quiet
		$a_01_2 = {4e 2d 41 2d 53 2d 41 2d 43 2d 52 2d 59 } //1 N-A-S-A-C-R-Y
		$a_01_3 = {52 45 43 4f 56 45 52 2d 46 49 4c 45 53 2d 52 45 41 44 4d 45 2d 57 41 52 4e 49 4e 47 } //1 RECOVER-FILES-README-WARNING
		$a_01_4 = {2d 4b 45 59 2d 52 45 41 44 4d 45 2e 74 78 74 } //1 -KEY-README.txt
		$a_01_5 = {45 4e 43 52 59 50 54 45 44 2d 46 49 4c 45 53 2d 41 4c 4c } //1 ENCRYPTED-FILES-ALL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
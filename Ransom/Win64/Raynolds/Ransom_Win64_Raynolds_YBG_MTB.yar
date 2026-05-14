
rule Ransom_Win64_Raynolds_YBG_MTB{
	meta:
		description = "Ransom:Win64/Raynolds.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 70 00 68 00 6f 00 73 00 20 00 55 00 49 00 2e 00 65 00 78 00 65 00 } //1 Sophos UI.exe
		$a_01_1 = {4d 00 73 00 4d 00 70 00 45 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //1 MsMpEng.exe
		$a_01_2 = {57 72 69 74 65 44 72 69 76 65 72 } //1 WriteDriver
		$a_01_3 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_4 = {54 6f 72 20 42 72 6f 77 73 65 72 } //1 Tor Browser
		$a_01_5 = {52 00 65 00 73 00 74 00 6f 00 72 00 65 00 59 00 6f 00 75 00 72 00 46 00 69 00 6c 00 65 00 73 00 } //1 RestoreYourFiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
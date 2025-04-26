
rule Ransom_Win64_Filecoder_NITC_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.NITC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //2 files are encrypted
		$a_01_1 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //2 decrypt your files
		$a_01_2 = {53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //2 Start Menu\Programs\Startup
		$a_01_3 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
		$a_01_4 = {57 41 52 4e 49 4e 47 } //1 WARNING
		$a_01_5 = {44 41 4e 47 45 52 } //1 DANGER
		$a_01_6 = {61 6e 74 69 76 69 72 75 73 20 73 6f 6c 75 74 69 6f 6e 73 } //1 antivirus solutions
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}
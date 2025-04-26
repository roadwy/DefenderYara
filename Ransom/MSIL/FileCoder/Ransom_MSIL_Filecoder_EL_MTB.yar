
rule Ransom_MSIL_Filecoder_EL_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {64 65 52 65 61 64 4d 65 21 21 21 2e 74 78 74 } //1 deReadMe!!!.txt
		$a_81_1 = {6b 69 6c 6c 2e 62 61 74 } //1 kill.bat
		$a_81_2 = {6b 69 6c 6c 6d 65 2e 62 61 74 } //1 killme.bat
		$a_81_3 = {64 6f 6e 6f 74 20 63 72 79 20 3a 29 } //1 donot cry :)
		$a_81_4 = {2e 63 72 69 6e 67 } //1 .cring
		$a_81_5 = {43 72 79 70 74 33 72 } //1 Crypt3r
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
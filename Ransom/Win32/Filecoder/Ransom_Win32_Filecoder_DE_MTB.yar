
rule Ransom_Win32_Filecoder_DE_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {48 4f 57 20 54 4f 20 42 41 43 4b 20 59 4f 55 52 20 46 49 4c 45 53 2e 65 78 65 } //1 HOW TO BACK YOUR FILES.exe
		$a_81_1 = {48 65 72 6d 65 73 } //1 Hermes
		$a_81_2 = {52 65 71 75 69 72 65 6d 65 6e 74 73 2e 70 64 62 } //1 Requirements.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
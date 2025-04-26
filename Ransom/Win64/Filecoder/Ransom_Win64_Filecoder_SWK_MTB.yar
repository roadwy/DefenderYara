
rule Ransom_Win64_Filecoder_SWK_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.SWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 5f 63 61 74 5f 65 6e 63 72 79 70 74 } //2 start_cat_encrypt
		$a_01_1 = {72 65 63 6f 76 65 72 20 66 69 6c 65 73 2c 76 69 65 77 20 68 65 72 65 2e 74 78 74 } //2 recover files,view here.txt
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /c vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
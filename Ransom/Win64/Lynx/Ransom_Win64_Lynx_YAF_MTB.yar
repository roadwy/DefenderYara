
rule Ransom_Win64_Lynx_YAF_MTB{
	meta:
		description = "Ransom:Win64/Lynx.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {77 65 20 61 72 65 20 4c 79 6e 78 20 47 72 6f 75 70 } //1 we are Lynx Group
		$a_01_1 = {61 74 74 61 63 6b 65 64 } //1 attacked
		$a_01_2 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //1 decrypt your files
		$a_01_3 = {73 74 61 72 74 20 6e 65 67 6f 74 69 61 74 69 6f 6e 73 } //1 start negotiations
		$a_01_4 = {66 69 6c 65 73 20 73 74 6f 6c 65 6e } //1 files stolen
		$a_01_5 = {69 6e 74 65 72 65 73 74 65 64 20 6f 6e 6c 79 20 69 6e 20 6d 6f 6e 65 79 } //1 interested only in money
		$a_01_6 = {6c 79 6e 78 63 68 61 74 } //10 lynxchat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=16
 
}

rule Ransom_Win64_FileCoder_TMX_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.TMX!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 48 01 48 8b 45 f0 48 8b 55 10 89 4c 24 28 48 8b 4d 18 48 89 4c 24 20 } //5
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {43 6f 6f 6b 69 65 73 } //1 Cookies
		$a_01_3 = {4d 79 43 6c 6f 6e 65 } //1 MyClone
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}
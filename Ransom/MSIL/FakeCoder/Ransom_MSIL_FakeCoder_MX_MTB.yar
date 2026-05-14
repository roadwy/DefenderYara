
rule Ransom_MSIL_FakeCoder_MX_MTB{
	meta:
		description = "Ransom:MSIL/FakeCoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 61 6e 6e 61 43 72 79 64 65 6d 6f 2e 70 64 62 } //1 WannaCrydemo.pdb
		$a_01_1 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 2e 00 6f 00 72 00 67 00 } //1 bitcoin.org
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {57 00 61 00 6e 00 61 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //1 WanaDecryptor
		$a_01_4 = {77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 } //1 wallpaper
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
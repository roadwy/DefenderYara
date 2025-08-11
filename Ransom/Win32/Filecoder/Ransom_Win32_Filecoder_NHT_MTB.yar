
rule Ransom_Win32_Filecoder_NHT_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.NHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21 } //1 Hello, World!
		$a_01_1 = {72 61 6e 73 6f 6d 2e 74 78 74 } //1 ransom.txt
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_01_3 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 73 65 6e 64 20 24 31 30 30 30 20 74 6f } //1 To decrypt your files, send $1000 to
		$a_01_4 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //1 ransom.jpg
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /im explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
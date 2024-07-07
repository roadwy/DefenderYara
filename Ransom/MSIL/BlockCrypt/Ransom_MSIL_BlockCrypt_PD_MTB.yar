
rule Ransom_MSIL_BlockCrypt_PD_MTB{
	meta:
		description = "Ransom:MSIL/BlockCrypt.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 } //1 Encrypt
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_2 = {77 00 61 00 6c 00 6c 00 2e 00 6a 00 70 00 67 00 } //1 wall.jpg
		$a_01_3 = {73 00 2e 00 62 00 61 00 74 00 } //1 s.bat
		$a_01_4 = {73 00 74 00 2e 00 62 00 61 00 74 00 } //1 st.bat
		$a_02_5 = {52 00 65 00 61 00 64 00 4d 00 65 00 21 00 90 02 10 2e 00 74 00 78 00 74 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}
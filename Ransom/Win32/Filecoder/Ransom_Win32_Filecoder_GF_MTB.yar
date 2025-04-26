
rule Ransom_Win32_Filecoder_GF_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {20 2f 64 65 6e 79 20 2a 53 2d 31 2d 31 2d 30 3a 28 4f 49 29 28 43 49 29 28 44 45 2c 44 43 29 } //1  /deny *S-1-1-0:(OI)(CI)(DE,DC)
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {2d 2d 41 75 74 6f 53 74 61 72 74 } //1 --AutoStart
		$a_81_3 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_81_4 = {4f 70 65 6e 53 65 72 76 69 63 65 57 } //1 OpenServiceW
		$a_81_5 = {59 63 74 58 54 39 62 71 } //1 YctXT9bq
		$a_81_6 = {64 65 6c 73 65 6c 66 2e 62 61 74 } //1 delself.bat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
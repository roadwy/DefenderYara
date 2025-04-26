
rule Ransom_Win32_RapidCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/RapidCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 72 61 70 69 64 } //1 .rapid
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 45 6e 63 72 79 70 74 4b 65 79 73 } //1 Software\EncryptKeys
		$a_01_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 45 4e 43 52 59 50 54 45 44 } //1 All your files have been ENCRYPTED
		$a_01_3 = {48 6f 77 20 52 65 63 6f 76 65 72 79 20 46 69 6c 65 73 2e 74 78 74 } //1 How Recovery Files.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
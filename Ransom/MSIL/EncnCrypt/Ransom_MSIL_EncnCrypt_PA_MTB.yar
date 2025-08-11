
rule Ransom_MSIL_EncnCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/EncnCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 00 42 00 54 00 43 00 25 00 } //1 %BTC%
		$a_01_1 = {42 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2e 00 62 00 6d 00 70 00 } //1 Background.bmp
		$a_01_2 = {5c 00 48 00 6f 00 77 00 20 00 54 00 6f 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 4d 00 79 00 20 00 46 00 69 00 6c 00 65 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 \How To Decrypt My Files.html
		$a_01_3 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 41 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //2 Ransomware Files Already Encrypted!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}
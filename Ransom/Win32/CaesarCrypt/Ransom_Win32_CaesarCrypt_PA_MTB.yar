
rule Ransom_Win32_CaesarCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/CaesarCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 52 45 41 44 4d 45 2e 54 58 54 } //1 \README.TXT
		$a_01_1 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 49 73 20 45 6e 63 72 79 70 74 65 64 20 4e 6f 77 } //1 All Your Files Is Encrypted Now
		$a_01_2 = {57 65 20 41 72 65 20 43 61 65 73 61 72 2e 20 57 65 20 4f 70 65 72 61 74 65 20 61 20 52 61 6e 73 6f 6d 77 61 72 65 20 4f 70 65 72 61 74 69 6f 6e 21 } //2 We Are Caesar. We Operate a Ransomware Operation!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}
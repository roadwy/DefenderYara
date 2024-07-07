
rule Ransom_Win32_UdochkCrypt_CM_MTB{
	meta:
		description = "Ransom:Win32/UdochkCrypt.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 65 20 67 6f 74 20 79 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 } //1 We got your documents and files encrypted
		$a_01_1 = {77 65 20 77 69 6c 6c 20 65 69 74 68 65 72 20 73 65 6e 64 20 74 68 6f 73 65 20 64 61 74 61 20 74 6f 20 72 69 76 61 6c 73 2c 20 6f 72 20 70 75 62 6c 69 73 68 20 74 68 65 6d 2e 20 47 44 50 52 } //1 we will either send those data to rivals, or publish them. GDPR
		$a_01_2 = {70 61 79 20 31 30 78 20 6d 6f 72 65 20 74 6f 20 74 68 65 20 67 6f 76 65 72 6e 6d 65 6e 74 } //1 pay 10x more to the government
		$a_01_3 = {57 61 73 20 69 73 74 20 67 65 72 61 64 65 20 70 61 73 73 69 65 72 74 3f } //1 Was ist gerade passiert?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
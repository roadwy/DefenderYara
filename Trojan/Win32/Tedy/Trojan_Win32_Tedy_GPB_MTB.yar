
rule Trojan_Win32_Tedy_GPB_MTB{
	meta:
		description = "Trojan:Win32/Tedy.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 6d 6e 72 67 6f 7a 78 77 76 65 69 6d 67 72 7a 77 76 72 71 74 65 62 67 70 78 61 74 75 68 68 79 6c 63 6f 73 67 64 61 70 77 68 61 7a 68 64 6a 62 76 71 68 79 76 72 75 67 70 63 61 65 } //1 dmnrgozxwveimgrzwvrqtebgpxatuhhylcosgdapwhazhdjbvqhyvrugpcae
		$a_01_1 = {6a 65 6a 79 79 6b 75 65 72 76 71 68 65 77 6e 7a 6a 6f 68 66 79 61 73 73 70 6e 6b 79 74 69 6f 79 62 78 66 71 } //1 jejyykuervqhewnzjohfyasspnkytioybxfq
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
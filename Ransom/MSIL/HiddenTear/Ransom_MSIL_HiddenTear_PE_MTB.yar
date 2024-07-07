
rule Ransom_MSIL_HiddenTear_PE_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //1 vssadmin delete shadows /all /Quiet
		$a_01_1 = {2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 5f 00 68 00 65 00 72 00 65 00 5f 00 6d 00 65 00 40 00 69 00 6e 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 65 00 6e 00 6a 00 65 00 79 00 } //1 .encrypted.contact_here_me@india.com.enjey
		$a_01_2 = {5c 00 52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //1 \README_DECRYPT.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
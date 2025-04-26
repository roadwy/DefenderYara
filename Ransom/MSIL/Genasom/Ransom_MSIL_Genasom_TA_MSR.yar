
rule Ransom_MSIL_Genasom_TA_MSR{
	meta:
		description = "Ransom:MSIL/Genasom.TA!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 45 6c 50 72 6f 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 72 61 6e 73 6f 6d 5c 72 61 6e 73 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 61 6e 73 6f 6d 2e 70 64 62 } //4 C:\Users\ElPro\source\repos\ransom\ransom\obj\Debug\ransom.pdb
		$a_01_1 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 ransom.Resources
		$a_01_2 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 66 00 69 00 6c 00 65 00 73 00 } //1 Decrypting files
		$a_01_3 = {59 00 4f 00 55 00 52 00 20 00 48 00 41 00 52 00 44 00 44 00 49 00 53 00 4b 00 53 00 20 00 48 00 41 00 56 00 45 00 20 00 42 00 45 00 45 00 4e 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 } //1 YOUR HARDDISKS HAVE BEEN ENCRYPTED
		$a_01_4 = {68 74 74 70 3a 2f 2f 62 32 78 68 49 47 30 7a 62 69 42 34 5a 41 2e 6f 6e 69 6f 6e } //1 http://b2xhIG0zbiB4ZA.onion
		$a_01_5 = {68 74 74 70 3a 2f 2f 34 6b 78 38 31 32 6e 6b 32 53 5a 39 33 63 4b 7a 32 39 30 2e 6f 6e 69 6f 6e } //1 http://4kx812nk2SZ93cKz290.onion
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
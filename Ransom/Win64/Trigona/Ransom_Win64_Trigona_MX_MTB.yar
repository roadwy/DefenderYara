
rule Ransom_Win64_Trigona_MX_MTB{
	meta:
		description = "Ransom:Win64/Trigona.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 00 72 00 79 00 20 00 74 00 6f 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 20 00 66 00 69 00 6c 00 65 00 } //1 Try to encrypt file
		$a_01_1 = {47 00 65 00 74 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 49 00 44 00 } //1 Get computer ID
		$a_01_2 = {2f 00 73 00 74 00 65 00 61 00 6c 00 74 00 68 00 } //1 /stealth
		$a_01_3 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 2e 00 } //1 Encryption completed.
		$a_01_4 = {4f 6e 65 50 61 74 68 45 6e 63 72 79 70 74 69 6f 6e } //1 OnePathEncryption
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
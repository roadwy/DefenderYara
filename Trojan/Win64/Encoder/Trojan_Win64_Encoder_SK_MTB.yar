
rule Trojan_Win64_Encoder_SK_MTB{
	meta:
		description = "Trojan:Win64/Encoder.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 43 4e 4d 53 42 4e 4d 53 4c } //1 .CNMSBNMSL
		$a_81_1 = {5c 52 45 41 44 5f 54 48 49 53 5f 46 49 52 53 54 2e 74 78 74 } //1 \READ_THIS_FIRST.txt
		$a_81_2 = {3a 20 31 41 31 7a 50 31 65 50 35 51 47 65 66 69 32 44 4d 50 54 66 54 4c 35 53 4c 6d 76 37 44 69 76 66 4e 61 } //1 : 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
		$a_81_3 = {3a 20 72 65 63 6f 76 65 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 : recover@protonmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
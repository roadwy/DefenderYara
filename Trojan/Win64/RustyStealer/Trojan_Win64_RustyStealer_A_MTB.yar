
rule Trojan_Win64_RustyStealer_A_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 c1 f7 d0 41 89 c7 41 21 cf 66 0f bc c0 0f b7 c0 48 c1 e0 05 48 89 fe 48 29 c6 48 8b 56 f0 4c 8b 46 f8 } //1
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
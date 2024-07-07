
rule Trojan_Win64_BarysStealer_EM_MTB{
	meta:
		description = "Trojan:Win64/BarysStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 0e 00 c0 69 0e 00 c7 69 0e 00 ce 69 0e 00 d4 69 0e 00 da 69 0e 00 e0 69 0e 00 e6 69 0e 00 ec 69 0e 00 fa 69 0e 00 00 6a 0e 00 0b 6a 0e 00 11 6a 0e 00 17 6a 0e } //7
		$a_01_1 = {69 0e 00 c4 69 0e 00 ca 69 0e 00 d0 69 0e 00 d6 69 0e 00 dc 69 0e 00 ea 69 0e 00 f0 69 0e 00 fb 69 0e 00 01 6a 0e 00 07 6a 0e } //7
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*7) >=7
 
}
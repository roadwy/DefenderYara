
rule Trojan_Win64_AlphaModule_A{
	meta:
		description = "Trojan:Win64/AlphaModule.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4e 74 43 72 65 61 74 65 53 65 63 74 69 6f 6e 20 2d 20 46 61 69 6c 00 00 70 4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 20 2d 20 46 61 69 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
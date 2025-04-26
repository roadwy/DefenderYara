
rule Trojan_BAT_Heracles_HNG_MTB{
	meta:
		description = "Trojan:BAT/Heracles.HNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 00 } //2
		$a_01_1 = {00 24 37 66 32 38 34 63 64 66 2d 35 63 61 38 2d 34 38 34 37 2d 38 66 34 37 2d 34 31 62 36 64 65 62 37 32 66 62 33 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}

rule Backdoor_BAT_DCRat_G_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0d 09 06 16 06 8e 69 6f ?? 00 00 0a 13 04 08 6f } //2
		$a_03_1 = {00 00 0a 11 04 6f ?? 00 00 0a 13 05 2b } //2
		$a_01_2 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //1 ProcessWindowStyle
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
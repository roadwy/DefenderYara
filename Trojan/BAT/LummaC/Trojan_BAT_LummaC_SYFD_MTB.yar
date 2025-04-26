
rule Trojan_BAT_LummaC_SYFD_MTB{
	meta:
		description = "Trojan:BAT/LummaC.SYFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 37 11 36 16 6f ?? 00 00 0a 61 d2 13 37 02 11 33 11 37 9c 11 33 17 58 13 33 } //2
		$a_03_1 = {91 11 2d 11 30 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 35 73 ?? 00 00 0a 13 36 11 36 11 2d 11 35 91 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
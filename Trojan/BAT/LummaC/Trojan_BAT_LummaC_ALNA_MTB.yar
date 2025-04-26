
rule Trojan_BAT_LummaC_ALNA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 36 11 35 16 6f ?? 00 00 0a 61 d2 13 36 02 11 32 11 36 9c 11 32 17 58 13 32 11 32 03 3f } //3
		$a_03_1 = {11 30 11 2d 11 2f 91 58 20 00 01 00 00 5d 13 30 73 ?? 00 00 0a 13 33 11 33 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}

rule Trojan_BAT_Rozena_AAAY_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AAAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 17 02 06 8f 90 01 01 00 00 01 25 47 03 06 03 8e 69 5d 91 61 d2 52 06 17 58 0a 06 02 8e 69 32 e3 90 00 } //2
		$a_01_1 = {07 09 06 5a 08 58 02 08 06 5a 09 58 91 9c 09 17 58 0d 09 06 32 ea } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
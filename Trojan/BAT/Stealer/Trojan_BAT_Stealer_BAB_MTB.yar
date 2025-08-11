
rule Trojan_BAT_Stealer_BAB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 07 09 6f 2b 00 00 0a 03 09 03 6f 29 00 00 0a 5d 6f 2b 00 00 0a 61 d1 6f 2e 00 00 0a 26 00 09 17 58 0d 09 07 6f 29 00 00 0a fe 04 13 04 11 04 2d cd } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
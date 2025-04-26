
rule Trojan_BAT_Lazy_SL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 05 06 17 58 13 09 06 20 00 90 01 00 5d 13 06 11 09 20 00 90 01 00 5d 13 0a 07 11 0a 91 11 05 58 13 0b 07 11 06 91 13 0c 11 07 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 06 11 0e 11 0b 59 11 05 5d d2 9c 06 17 58 0a 06 20 00 90 01 00 32 a9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
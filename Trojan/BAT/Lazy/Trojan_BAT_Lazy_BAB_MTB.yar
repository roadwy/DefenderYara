
rule Trojan_BAT_Lazy_BAB_MTB{
	meta:
		description = "Trojan:BAT/Lazy.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 09 91 13 04 11 04 20 aa 00 00 00 61 d2 13 04 11 04 09 20 00 01 00 00 5d d2 59 d2 13 04 11 04 19 63 11 04 1b 62 60 d2 13 04 11 04 03 09 03 8e 69 5d 91 61 d2 13 04 08 09 11 04 9c 09 17 58 0d 09 02 8e 69 32 ba } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
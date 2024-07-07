
rule Trojan_BAT_zgRAT_MBFN_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.MBFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 08 11 06 11 10 11 05 5d d2 9c 07 17 58 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
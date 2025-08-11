
rule Trojan_BAT_Zusy_GPAN_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GPAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 8e 69 5d 91 61 d2 81 ?? 00 00 01 11 08 17 58 13 08 11 08 11 06 8e 69 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
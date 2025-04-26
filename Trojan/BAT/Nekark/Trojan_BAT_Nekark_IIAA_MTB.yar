
rule Trojan_BAT_Nekark_IIAA_MTB{
	meta:
		description = "Trojan:BAT/Nekark.IIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 04 08 20 ?? 02 00 00 58 20 ?? 02 00 00 59 1b 59 1b 58 04 8e 69 5d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
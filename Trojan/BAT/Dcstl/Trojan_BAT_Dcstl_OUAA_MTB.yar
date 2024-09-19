
rule Trojan_BAT_Dcstl_OUAA_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.OUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 91 11 05 61 13 06 11 04 17 58 07 8e 69 5d 13 07 07 11 07 91 13 08 11 06 11 08 59 13 09 07 11 04 11 09 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 04 17 58 13 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
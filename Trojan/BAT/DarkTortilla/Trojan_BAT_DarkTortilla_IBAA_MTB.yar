
rule Trojan_BAT_DarkTortilla_IBAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.IBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 1e 5d 16 fe 01 13 07 11 07 2c 0c 02 11 06 02 11 06 91 1f 5d 61 b4 9c 11 06 17 d6 13 06 11 06 11 05 31 db } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}

rule Trojan_BAT_DarkTortilla_ORAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ORAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0c 02 11 05 02 11 05 91 1f ?? 61 b4 9c 11 05 17 d6 13 05 11 05 11 04 31 db } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
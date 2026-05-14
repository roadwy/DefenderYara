
rule Trojan_BAT_DarkTortilla_LPZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.LPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1e 5d 16 fe 01 13 05 11 05 2c 10 07 11 04 07 11 04 91 20 bc 00 00 00 61 b4 9c 00 00 11 04 17 d6 13 04 11 04 09 31 d7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
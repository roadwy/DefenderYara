
rule Trojan_BAT_DarkTortilla_IEAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.IEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1d 5d 16 fe 01 0d 09 2c 0a 02 08 02 08 91 1f 34 61 b4 9c 08 17 d6 0c 08 07 31 e4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
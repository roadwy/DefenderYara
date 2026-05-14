
rule Trojan_BAT_DarkTortilla_SIVX_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SIVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 05 08 11 05 91 07 61 9c 11 05 1b d6 13 05 11 05 11 04 31 ea } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
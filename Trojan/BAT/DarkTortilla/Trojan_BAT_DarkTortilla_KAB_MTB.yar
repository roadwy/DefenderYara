
rule Trojan_BAT_DarkTortilla_KAB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1d 5d 16 fe 01 13 05 11 05 2c 0c 02 11 04 02 11 04 91 1f 53 61 b4 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
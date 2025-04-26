
rule Trojan_BAT_DarkTortilla_ADT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 16 fe 01 13 04 11 04 2c 22 08 18 9a 74 74 00 00 01 20 3b 6b 20 00 08 16 9a 74 74 00 00 01 16 20 00 ee 02 00 28 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
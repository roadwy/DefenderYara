
rule Trojan_BAT_Zilla_SOO_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 60 00 00 0a 28 87 00 00 0a 13 06 00 11 06 13 07 16 13 08 2b 66 11 07 11 08 9a 13 09 00 11 09 73 88 00 00 0a 13 0a 11 09 28 46 00 00 0a 13 0b 11 0b 28 47 00 00 0a 13 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
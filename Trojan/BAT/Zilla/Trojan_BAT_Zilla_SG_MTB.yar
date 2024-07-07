
rule Trojan_BAT_Zilla_SG_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 08 00 00 0a 6f 09 00 00 0a 7e 01 00 00 04 28 0a 00 00 0a 28 0b 00 00 0a 0a } //1
		$a_01_1 = {06 72 01 00 00 70 28 02 00 00 06 28 10 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
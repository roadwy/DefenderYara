
rule Trojan_BAT_Zilla_MKC_MTB{
	meta:
		description = "Trojan:BAT/Zilla.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 15 00 00 06 28 17 00 00 06 0a 06 28 23 00 00 0a 0b 1a 8d 03 00 00 01 0d 09 16 72 11 00 00 70 a2 09 17 07 6f 24 00 00 0a } //20
		$a_01_1 = {14 14 6f 25 00 00 0a 28 11 00 00 0a a2 09 18 72 19 00 00 70 a2 09 19 72 27 00 00 70 a2 09 0c } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}
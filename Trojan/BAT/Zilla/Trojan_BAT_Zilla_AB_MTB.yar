
rule Trojan_BAT_Zilla_AB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 6f 12 00 00 0a a5 11 00 00 01 0c 08 0a 7e 02 00 00 04 12 02 28 13 00 00 0a 28 14 00 00 0a 6f 15 00 00 0a 0d 09 28 16 00 00 0a 72 21 00 00 70 28 02 00 00 06 13 04 7e 01 00 00 04 72 69 00 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
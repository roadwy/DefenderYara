
rule Trojan_BAT_Zilla_IJ_MTB{
	meta:
		description = "Trojan:BAT/Zilla.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 f9 01 00 70 28 07 00 00 06 11 05 28 17 00 00 0a 28 2d 00 00 0a 72 25 02 00 70 28 07 00 00 06 11 04 28 17 00 00 0a 28 2d 00 00 0a 73 2e 00 00 0a } //2
		$a_01_1 = {6f 32 00 00 0a 11 0b 17 6f 33 00 00 0a 11 0b 28 34 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}

rule Trojan_BAT_Zilla_SIRT_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SIRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 0d 22 00 70 28 3b 00 00 0a 00 72 53 14 00 70 28 3b 00 00 0a 00 72 3f 22 00 70 28 3c 00 00 0a 00 28 3d 00 00 0a 0a 12 00 28 3e 00 00 0a 0b 28 3f 00 00 0a 00 02 07 28 57 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
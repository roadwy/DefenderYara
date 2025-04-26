
rule Trojan_BAT_Zilla_SED_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 02 03 05 1e 28 4f 00 00 06 0b 02 7b 63 00 00 04 07 06 04 ba 28 59 00 00 0a 7e 06 00 00 0a 28 3d 00 00 06 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
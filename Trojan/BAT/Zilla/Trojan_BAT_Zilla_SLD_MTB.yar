
rule Trojan_BAT_Zilla_SLD_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7d 2d 00 00 04 02 17 7d 2a 00 00 04 02 28 2d 00 00 06 0a 73 3c 00 00 06 0b 07 06 16 6f 3f 00 00 06 2d 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}

rule Trojan_BAT_plugx_psyI_MTB{
	meta:
		description = "Trojan:BAT/plugx.psyI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 15 00 00 06 0a 06 7e 14 00 00 0a 7d 07 00 00 04 06 fe 06 16 00 00 06 73 15 00 00 0a 73 16 00 00 0a 0b 07 16 6f 17 00 00 0a 07 6f 18 00 00 0a 07 6f 19 00 00 0a } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
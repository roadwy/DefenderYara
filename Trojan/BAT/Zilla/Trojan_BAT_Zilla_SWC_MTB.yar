
rule Trojan_BAT_Zilla_SWC_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 a3 00 00 06 2d 06 16 28 ?? 00 00 0a 14 fe 06 98 00 00 06 73 2f 00 00 0a 73 30 00 00 0a 0b 14 fe 06 27 00 00 06 73 2f 00 00 0a 73 30 00 00 0a 0a 28 ?? 00 00 06 80 0a 00 00 04 07 6f ?? 00 00 0a 06 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
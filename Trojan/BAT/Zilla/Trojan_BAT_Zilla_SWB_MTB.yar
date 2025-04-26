
rule Trojan_BAT_Zilla_SWB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 28 24 00 00 0a 00 00 02 28 ?? 00 00 06 00 02 28 ?? 00 00 06 16 fe 01 0a 06 2c 0b 00 02 28 ?? 00 00 06 00 00 2b 17 00 02 28 ?? 00 00 06 00 02 28 ?? 00 00 06 26 02 28 ?? 00 00 06 26 00 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
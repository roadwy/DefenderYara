
rule Trojan_BAT_Zilla_SLEW_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 00 70 0a 72 ?? 03 00 70 0b 73 41 00 00 0a 0c 00 08 06 07 6f 42 00 00 0a 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
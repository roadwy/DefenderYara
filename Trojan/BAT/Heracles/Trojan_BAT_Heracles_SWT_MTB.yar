
rule Trojan_BAT_Heracles_SWT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 09 00 00 70 28 02 00 00 06 de 03 26 de 00 20 b8 0b 00 00 28 05 00 00 0a 1f ?? 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a 28 08 00 00 0a 1f 23 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
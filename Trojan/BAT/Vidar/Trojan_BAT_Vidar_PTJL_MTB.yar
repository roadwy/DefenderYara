
rule Trojan_BAT_Vidar_PTJL_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 07 00 00 06 38 9f 00 00 00 28 ?? 00 00 06 72 5c 01 00 70 28 ?? 00 00 0a 6f 24 00 00 0a 28 ?? 00 00 06 13 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
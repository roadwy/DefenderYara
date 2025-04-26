
rule Trojan_BAT_MSILZilla_PSPM_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.PSPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 07 00 00 0a 07 6f 08 00 00 0a 08 6f 07 00 00 0a 16 6f 09 00 00 0a 08 6f 07 00 00 0a 17 6f 0a 00 00 0a 08 6f 0b 00 00 0a 26 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
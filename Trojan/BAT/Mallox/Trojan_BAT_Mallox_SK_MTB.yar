
rule Trojan_BAT_Mallox_SK_MTB{
	meta:
		description = "Trojan:BAT/Mallox.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 72 01 00 00 70 6f 04 00 00 0a 6f 05 00 00 0a 6f 06 00 00 0a 6f 07 00 00 0a 6f 08 00 00 0a 0a dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
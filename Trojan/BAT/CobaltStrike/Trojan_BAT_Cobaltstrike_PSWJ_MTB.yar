
rule Trojan_BAT_Cobaltstrike_PSWJ_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PSWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 6f ?? 00 00 0a 26 06 6f ?? 00 00 0a 0b 72 1f 00 00 70 0c 07 08 6f ?? 00 00 0a 00 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
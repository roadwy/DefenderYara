
rule Trojan_BAT_Cobaltstrike_PSNH_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PSNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 03 0a 0a 28 90 01 03 0a 06 6f 90 01 03 0a 0b 07 28 90 01 03 0a 02 7b 01 00 00 04 72 c4 10 00 70 07 6f 05 00 00 06 28 90 01 03 0a 02 7b 01 00 00 04 6f 06 00 00 06 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
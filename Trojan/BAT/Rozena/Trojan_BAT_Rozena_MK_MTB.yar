
rule Trojan_BAT_Rozena_MK_MTB{
	meta:
		description = "Trojan:BAT/Rozena.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 08 72 01 00 00 70 6f 04 00 00 0a 08 72 94 00 00 70 6f 05 00 00 0a 08 16 6f 06 00 00 0a 08 17 6f 07 00 00 0a 08 17 6f 08 00 00 0a 08 17 6f 09 00 00 0a 08 17 6f 0a 00 00 0a 08 0a 06 28 0b 00 00 0a } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}
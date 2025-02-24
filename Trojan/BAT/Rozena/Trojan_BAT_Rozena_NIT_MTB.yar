
rule Trojan_BAT_Rozena_NIT_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 05 00 00 06 0a 06 16 28 06 00 00 06 26 [0-05] 28 08 00 00 06 0b 07 28 09 00 00 06 2a } //2
		$a_03_1 = {7e 03 00 00 04 2d 11 14 fe 06 0a 00 00 06 73 02 00 00 0a 80 03 00 00 04 7e 03 00 00 04 28 ?? 00 00 0a 74 02 00 00 01 28 ?? 00 00 0a 73 05 00 00 0a 0a 06 02 6f ?? 00 00 0a 0b 07 2a } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
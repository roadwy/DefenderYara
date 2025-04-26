
rule Trojan_BAT_Androm_SWA_MTB{
	meta:
		description = "Trojan:BAT/Androm.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 7b 06 00 00 04 06 8f 03 00 00 02 28 09 00 00 06 06 17 58 0a 06 6e 17 02 7b 07 00 00 04 1f 1f 5f 62 6a 32 db } //2
		$a_01_1 = {06 17 62 02 7b 06 00 00 04 06 8f 03 00 00 02 03 28 0a 00 00 06 58 0a 07 17 59 0b 07 16 30 e1 06 17 02 7b 07 00 00 04 1f 1f 5f 62 59 2a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
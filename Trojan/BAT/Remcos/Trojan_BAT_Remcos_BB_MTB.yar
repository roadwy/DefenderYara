
rule Trojan_BAT_Remcos_BB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 06 00 fe 0c 03 00 fe 0c 05 00 94 58 fe 0c 04 00 fe 0c 05 00 94 58 28 6b 00 00 06 28 50 00 00 0a 5d fe 0e 06 00 fe 0c 03 00 fe 0c 05 00 94 fe 0e 0b 00 fe 0c 03 00 fe 0c 05 00 fe 0c 03 00 fe 0c 06 00 94 9e fe 0c 03 00 fe 0c 06 00 fe 0c 0b 00 9e fe 0c 05 00 20 01 00 00 00 58 fe 0e 05 00 fe 0c 05 00 28 6c 00 00 06 28 50 00 00 0a 3f 8c ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
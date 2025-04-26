
rule Trojan_BAT_Stealer_AJEA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AJEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 74 6e 00 00 01 6f ?? 00 00 0a 13 0c 11 0c 74 6f 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 0a dd } //3
		$a_03_1 = {04 13 07 16 13 08 1a 13 11 2b c0 11 07 74 0b 00 00 1b 11 08 9a 13 09 07 75 0c 00 00 1b 11 09 75 4c 00 00 01 1f 10 28 ?? 00 00 0a 6f 6d 00 00 0a } //2
		$a_01_2 = {11 08 11 07 74 0b 00 00 1b 8e 69 fe 04 13 0a 11 0a } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}
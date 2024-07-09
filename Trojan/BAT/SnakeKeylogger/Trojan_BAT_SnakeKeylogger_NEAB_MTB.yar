
rule Trojan_BAT_SnakeKeylogger_NEAB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {a2 14 14 14 28 ?? 00 00 0a 14 72 ?? 46 02 70 18 8d ?? 00 00 01 25 16 72 ?? 46 02 70 a2 25 17 72 ?? 46 02 70 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 0a 2b 00 06 2a } //10
		$a_01_1 = {67 65 74 5f 4e 61 6b 65 64 5f 42 65 61 75 74 79 } //2 get_Naked_Beauty
		$a_01_2 = {4e 75 64 65 5f 50 68 6f 74 6f 73 5f } //2 Nude_Photos_
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}

rule Trojan_BAT_Vidar_MC_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 25 17 58 0b 09 a4 24 00 00 02 08 17 58 0c 08 02 8e 69 32 95 06 07 16 16 28 ?? 00 00 06 2a } //1
		$a_01_1 = {57 17 a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 58 00 00 00 2c 00 00 00 4f 00 00 00 99 00 00 00 80 00 00 00 14 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
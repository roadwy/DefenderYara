
rule Trojan_BAT_Loki_C_MTB{
	meta:
		description = "Trojan:BAT/Loki.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 1a 58 0a } //2
		$a_01_1 = {11 04 17 58 } //2 Б堗
		$a_03_2 = {06 16 08 74 ?? ?? ?? 1b 06 1a } //2
		$a_01_3 = {0b 07 07 5a 1a 5a 8d } //2
		$a_03_4 = {01 0d 08 74 ?? ?? ?? 1b 1a 09 74 ?? ?? ?? 1b 16 09 75 ?? ?? ?? 1b 8e 69 28 } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*4) >=12
 
}
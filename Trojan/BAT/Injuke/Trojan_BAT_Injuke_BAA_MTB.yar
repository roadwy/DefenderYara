
rule Trojan_BAT_Injuke_BAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 15 06 07 8f 1a 00 00 01 25 47 7e 02 00 00 04 61 d2 52 07 17 58 0b 07 06 8e 69 32 e5 28 ?? 00 00 0a 06 6f ?? 00 00 0a 2a } //5
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}

rule Trojan_BAT_Remcos_ABGM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 09 07 09 1e d8 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 09 17 d6 0d 09 11 04 31 e4 } //2
		$a_03_1 = {13 07 d0 34 ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 17 8d ?? ?? ?? 01 13 0c 11 0c 16 11 07 a2 11 0c 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 13 06 } //2
		$a_01_2 = {62 00 36 00 32 00 63 00 33 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 b62c3.resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
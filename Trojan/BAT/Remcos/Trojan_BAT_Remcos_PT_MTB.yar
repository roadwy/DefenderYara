
rule Trojan_BAT_Remcos_PT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 06 00 00 06 28 05 00 00 06 6f ?? ?? ?? 0a 0a 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 0c 7e ?? ?? ?? 04 } //2
		$a_03_1 = {20 00 01 00 00 72 ?? ?? ?? 70 14 d0 03 00 00 02 28 ?? ?? ?? 0a 17 8d ?? ?? ?? 01 } //2
		$a_03_2 = {09 20 00 01 00 00 6f ?? ?? ?? 0a 09 20 80 00 00 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 e8 03 00 00 73 ?? ?? ?? 0a 13 05 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}
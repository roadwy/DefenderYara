
rule Trojan_BAT_Remcos_PG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 0b 07 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0c 08 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 73 } //1
		$a_03_1 = {0a 0d 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f } //1
		$a_03_2 = {0a 14 18 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a a2 25 17 06 28 ?? ?? ?? 0a a2 6f ?? ?? ?? 0a 26 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
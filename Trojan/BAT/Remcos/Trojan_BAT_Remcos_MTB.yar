
rule Trojan_BAT_Remcos_MTB{
	meta:
		description = "Trojan:BAT/Remcos!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 12 00 00 06 25 28 19 00 ?? ?? 28 04 00 ?? ?? 28 0b 00 ?? ?? 7d 05 00 ?? ?? 13 01 20 00 00 ?? ?? 7e 2c 00 ?? ?? 7b 4b 00 ?? ?? 3a b0 ff ?? ?? 26 20 00 00 ?? ?? 38 a5 ff ff ff } //6
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1) >=7
 
}

rule Trojan_BAT_RemcosRAT_NRA_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 73 02 00 00 0a 0c 2b 0b 28 ?? 00 00 0a 2b eb 13 04 2b eb 73 ?? 00 00 0a 0b 08 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a de 07 } //5
		$a_01_1 = {4c 00 6f 00 78 00 61 00 64 00 } //1 Loxad
		$a_01_2 = {41 00 7a 00 73 00 74 00 65 00 } //1 Azste
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_RemcosRAT_NRA_MTB_2{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 0c 00 00 0a 13 20 11 1a 73 ?? ?? 00 0a 13 21 11 21 11 20 16 73 ?? ?? 00 0a 13 22 11 22 28 ?? ?? 00 0a 73 ?? ?? 00 0a 13 23 11 14 6f ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 24 11 23 6f ?? ?? 00 0a 28 ?? ?? 00 0a } //5
		$a_01_1 = {65 00 5a 00 59 00 57 00 77 00 45 00 4a 00 52 00 6e 00 42 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 } //1 eZYWwEJRnBprivate
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
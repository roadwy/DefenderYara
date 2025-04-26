
rule Trojan_BAT_Bladabindi_JK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0b 06 07 16 1a 6f ?? ?? ?? 0a 26 07 16 28 ?? ?? ?? 0a 0c 06 16 73 ?? ?? ?? 0a 0d 08 8d ?? ?? ?? 01 13 04 09 11 04 16 08 6f ?? ?? ?? 0a 26 11 04 13 05 de 14 09 2c 06 09 6f ?? ?? ?? 0a dc } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
		$a_80_2 = {47 65 74 44 6f 6d 61 69 6e } //GetDomain  1
		$a_80_3 = {44 65 63 6f 6d 70 72 65 73 73 } //Decompress  1
		$a_80_4 = {50 61 79 6c 6f 61 64 } //Payload  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}
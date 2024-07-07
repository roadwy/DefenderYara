
rule Trojan_BAT_AgentTesla_AIV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_03_0 = {17 da 13 06 16 13 07 2b 2d 07 11 04 11 07 6f 90 01 03 0a 13 08 07 11 04 11 07 6f 90 01 03 0a 13 09 11 09 28 90 01 03 0a 13 0a 08 06 11 0a b4 9c 11 07 17 d6 13 07 11 07 11 06 31 cd 90 00 } //10
		$a_03_1 = {a2 25 13 04 14 14 17 8d 90 01 03 01 25 16 17 9c 25 13 05 28 90 01 03 0a 11 05 16 91 2d 02 2b 0b 11 04 16 9a 28 90 01 03 0a 10 01 74 90 01 03 01 0b 07 6f 90 01 03 0a 1f 0b 9a 0c 19 8d 19 90 00 } //10
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=14
 
}

rule Trojan_BAT_AgentTesla_AGT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 4d 16 0c 2b 3b 16 0d 2b 29 11 07 06 08 58 07 09 58 6f ?? ?? ?? 0a 13 0f 12 0f 28 ?? ?? ?? 0a 13 09 11 05 11 04 11 09 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0a 11 0a 2d cd } //2
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 53 00 61 00 6e 00 50 00 68 00 61 00 6d 00 } //1 QuanLySanPham
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AGT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 09 11 05 6f ?? ?? ?? 0a 13 06 04 09 11 05 6f ?? ?? ?? 0a 13 07 11 07 28 ?? ?? ?? 0a 13 08 07 06 11 08 28 ?? ?? ?? 0a 9c 11 05 17 d6 13 05 11 05 11 04 31 cb } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_3 = {52 65 76 65 72 73 65 } //Reverse  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}

rule Trojan_BAT_AgentTesla_AKA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 0a 2b 13 09 06 07 06 91 08 06 08 8e 69 5d 91 61 d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 06 11 06 2d e1 } //2
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 2e 00 49 00 4d 00 45 00 48 00 65 00 6c 00 70 00 65 00 72 00 } //1 WindowsForms.IMEHelper
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AKA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 02 28 90 01 03 06 a2 6f 90 01 18 16 9a 25 72 90 01 03 70 20 00 02 00 00 14 14 14 6f 90 01 03 0a 0a 25 6f 90 01 03 0a 16 9a 6f 90 01 03 0a 20 00 01 00 00 14 06 17 8d 90 01 03 01 25 16 03 a2 90 00 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //GetExportedTypes  2
		$a_80_3 = {47 65 74 4d 65 74 68 6f 64 73 } //GetMethods  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}
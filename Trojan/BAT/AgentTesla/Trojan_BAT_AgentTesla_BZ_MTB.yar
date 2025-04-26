
rule Trojan_BAT_AgentTesla_BZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {0a 0c 02 72 ?? ?? ?? ?? 15 16 28 ?? ?? ?? ?? 0a 06 13 05 16 13 04 2b 29 11 05 11 04 9a 0d 08 72 ?? ?? ?? ?? 09 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 26 11 04 17 d6 13 04 00 11 04 11 05 8e b7 fe 04 13 06 11 06 2d c9 08 6f ?? ?? ?? ?? 0b 2b 00 07 2a } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_BZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 62 76 73 4f 43 63 4f 42 5a 68 7a 71 61 48 } //2 EbvsOCcOBZhzqaH
		$a_01_1 = {3d 00 3d 00 3d 00 3d 00 3d 00 4d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 61 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 69 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 6e 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 } //1 =====M============a==============i=============n=========
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
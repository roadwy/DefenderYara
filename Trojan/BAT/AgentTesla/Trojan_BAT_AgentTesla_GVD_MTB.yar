
rule Trojan_BAT_AgentTesla_GVD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 08 91 08 03 28 2b 04 00 06 9c 08 17 d6 0c 08 07 31 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_GVD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 61 00 74 00 62 00 6f 00 78 00 2e 00 6d 00 6f 00 65 00 } //3 https://files.catbox.moe
		$a_01_1 = {79 64 30 34 39 39 36 38 32 34 38 32 36 34 33 39 34 62 65 66 36 34 64 62 39 31 36 38 30 38 62 66 64 } //1 yd049968248264394bef64db916808bfd
		$a_01_2 = {52 75 6e 41 73 44 65 74 61 69 6c 65 64 43 6f 6e 76 65 72 74 65 72 } //1 RunAsDetailedConverter
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
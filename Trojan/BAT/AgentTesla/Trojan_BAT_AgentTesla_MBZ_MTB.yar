
rule Trojan_BAT_AgentTesla_MBZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 06 93 0b 06 18 58 93 07 61 0b 11 0f 20 ?? 00 00 00 93 } //2
		$a_01_1 = {33 66 34 32 66 36 63 31 37 35 63 } //1 3f42f6c175c
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_MBZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 00 6e 00 6e 00 00 09 4c 00 6f 00 61 00 64 } //2
		$a_01_1 = {44 00 65 00 6c 00 69 00 76 00 65 00 72 00 79 00 4d 00 61 00 72 00 6b 00 65 00 74 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
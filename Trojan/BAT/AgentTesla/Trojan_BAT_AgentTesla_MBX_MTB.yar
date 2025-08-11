
rule Trojan_BAT_AgentTesla_MBX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 20 00 c8 00 00 0c 07 08 } //2
		$a_01_1 = {46 00 59 00 00 07 70 00 70 00 36 } //1
		$a_01_2 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //1 GetExportedTypes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
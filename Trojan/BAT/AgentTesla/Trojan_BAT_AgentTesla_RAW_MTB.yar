
rule Trojan_BAT_AgentTesla_RAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 17 b6 09 09 0b 00 00 00 fa ?? 33 00 16 00 00 01 00 00 00 66 00 00 00 2b 00 00 00 0d 01 00 00 ?? ?? 00 00 cd 01 00 00 12 00 00 00 c3 00 00 00 5d 00 00 00 ?? 00 00 00 12 00 00 00 12 00 00 00 13 00 00 00 5b 00 00 00 d7 00 00 00 06 00 00 00 01 00 00 00 05 00 00 00 02 00 00 00 0b 00 00 00 01 } //1
		$a_81_1 = {53 74 6f 72 6d 43 61 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 StormCast.Properties.Resources
		$a_81_2 = {67 65 74 5f 76 67 } //1 get_vg
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
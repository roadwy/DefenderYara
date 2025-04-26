
rule Trojan_BAT_AgentTesla_EDP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {2b 1f 0a 2b fb 20 e7 03 00 00 ?? 2d 0a 26 06 17 59 ?? 2d 0a 26 2b 0a 28 17 00 00 0a 2b f0 0a 2b 00 06 16 fe 03 0c 08 2d dc } //10
		$a_80_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //GetExecutingAssembly  3
		$a_80_2 = {47 65 74 44 6f 6d 61 69 6e } //GetDomain  3
		$a_80_3 = {41 6e 69 6d 61 6c 73 20 72 75 6e } //Animals run  3
		$a_80_4 = {48 75 6d 61 6e 73 20 72 75 6e } //Humans run  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}
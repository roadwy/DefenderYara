
rule Trojan_BAT_AgentTesla_NWD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {1f 2d 7e 30 00 00 04 20 a3 02 00 00 95 9e 7e 39 00 00 04 1f 42 8f 07 00 00 01 25 71 07 00 00 01 7e 30 00 00 04 20 4c 03 00 00 95 61 81 07 00 00 01 2a 7e 39 00 00 04 1f 42 95 7e 30 00 00 04 20 25 03 00 00 95 40 c1 00 00 00 7e 0d 00 00 04 19 } //1
		$a_01_1 = {57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 } //1
		$a_01_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
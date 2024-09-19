
rule Trojan_BAT_AgentTesla_MVS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 06 16 06 8e 69 6f 60 00 00 0a 0d 09 28 61 00 00 0a 13 04 } //1
		$a_00_1 = {32 38 37 35 66 39 32 63 2d 64 66 63 35 2d 34 36 66 36 2d 38 64 34 66 2d 63 37 63 31 38 65 63 35 33 36 34 62 } //1 2875f92c-dfc5-46f6-8d4f-c7c18ec5364b
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
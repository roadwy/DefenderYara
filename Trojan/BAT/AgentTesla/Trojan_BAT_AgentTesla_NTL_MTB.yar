
rule Trojan_BAT_AgentTesla_NTL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 fd a3 3d 09 0e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 3a 00 00 00 24 00 00 00 39 00 00 00 4e 00 00 00 b1 00 00 00 47 00 00 00 01 00 00 00 0f 00 00 00 40 00 00 00 01 00 00 00 07 00 00 00 11 00 00 00 07 } //1
		$a_01_1 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 } //1 base64EncodedData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
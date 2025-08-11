
rule Trojan_BAT_AgentTesla_RAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 3d a2 1d 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5f 00 00 00 0d 00 00 00 35 00 00 00 3c 00 00 00 2d 00 00 00 aa 00 00 00 0b 00 00 00 30 00 00 00 01 00 00 00 0f 00 00 00 07 00 00 00 14 00 00 00 1e 00 00 00 02 00 00 00 06 00 00 00 03 00 00 00 01 00 00 00 07 00 00 00 02 } //1
		$a_81_1 = {67 65 74 5f 62 73 } //1 get_bs
		$a_81_2 = {42 61 63 6b 45 6e 64 4c 69 62 72 61 72 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 BackEndLibrary.Properties.Resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
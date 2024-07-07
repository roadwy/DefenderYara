
rule Trojan_BAT_AgentTesla_OXY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {0d 09 16 08 16 1e 28 90 01 05 06 08 6f 90 01 05 06 18 6f 90 01 05 06 6f 90 01 04 02 16 02 8e 69 6f 90 01 04 13 04 11 04 13 05 2b 00 11 05 2a 90 00 } //10
		$a_80_1 = {43 61 70 74 49 74 } //CaptIt  2
		$a_80_2 = {67 65 74 5f 43 61 70 74 49 74 } //get_CaptIt  2
		$a_80_3 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //SymmetricAlgorithm  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}
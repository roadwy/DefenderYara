
rule Trojan_BAT_AgentTesla_BI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 4b 63 68 53 77 44 4d 30 61 63 43 42 30 39 33 47 31 } //1 RKchSwDM0acCB093G1
		$a_01_1 = {69 30 66 70 56 74 77 6d 65 32 46 49 42 32 64 73 73 35 } //1 i0fpVtwme2FIB2dss5
		$a_01_2 = {64 49 4b 33 4c 59 59 33 74 66 61 4e 39 4f 46 53 4b 77 } //1 dIK3LYY3tfaN9OFSKw
		$a_01_3 = {57 65 62 6a 47 6c 4b 54 41 48 48 35 72 57 43 44 6c 37 } //1 WebjGlKTAHH5rWCDl7
		$a_01_4 = {4a 32 74 6b 34 4a 38 6d 37 39 32 47 74 76 44 46 56 39 } //1 J2tk4J8m792GtvDFV9
		$a_01_5 = {70 6a 61 6b 31 76 6b 39 57 58 33 50 50 66 53 57 74 74 } //1 pjak1vk9WX3PPfSWtt
		$a_01_6 = {66 48 5a 6b 44 31 72 31 61 39 63 56 74 53 62 68 76 5a } //1 fHZkD1r1a9cVtSbhvZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}

rule Trojan_BAT_AgentTesla_DZB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {42 00 75 00 2d 00 6e 00 69 00 2d 00 2d 00 66 00 75 00 5f 00 54 00 2d 00 2d 00 65 00 78 00 2d 00 2d 00 74 00 42 00 6f 00 2d 00 2d 00 2d 00 78 00 } //1 Bu-ni--fu_T--ex--tBo---x
		$a_01_1 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00 } //1
		$a_01_2 = {00 44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 00 } //1 䐀扥杵楧杮潍敤s
		$a_01_3 = {00 52 65 70 6c 61 63 65 00 } //1
		$a_01_4 = {00 46 72 6f 6d 42 61 73 65 36 34 } //1
		$a_01_5 = {00 47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 00 } //1 䜀瑥硅潰瑲摥祔数s
		$a_01_6 = {00 49 6e 76 6f 6b 65 } //1
		$a_01_7 = {00 47 65 74 4d 65 74 68 6f 64 } //1 䜀瑥敍桴摯
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
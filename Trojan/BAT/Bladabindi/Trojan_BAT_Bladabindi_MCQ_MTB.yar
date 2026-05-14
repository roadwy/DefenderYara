
rule Trojan_BAT_Bladabindi_MCQ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {79 00 70 00 6f [0-3b] 74 00 6e 00 69 00 00 09 72 00 74 00 6e 00 45 } //1
		$a_01_1 = {64 69 73 69 75 64 73 75 69 6f 64 73 69 6f 75 64 73 75 69 6f 75 69 6f 64 73 69 75 6f 64 73 69 75 6f 64 73 69 75 6f 64 73 6f 75 } //1 disiudsuiodsioudsuiouiodsiuodsiuodsiuodsou
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
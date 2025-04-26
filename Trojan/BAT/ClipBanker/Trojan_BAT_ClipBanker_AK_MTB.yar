
rule Trojan_BAT_ClipBanker_AK_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 00 6e 00 63 00 6d 00 78 00 64 00 66 00 6a 00 6b 00 66 00 64 00 6a 00 68 00 75 00 74 00 79 00 74 00 79 00 35 00 38 00 37 00 34 00 39 00 39 00 30 00 34 00 33 00 } //1 vncmxdfjkfdjhutyty587499043
		$a_01_1 = {77 00 65 00 70 00 6f 00 65 00 6f 00 69 00 66 00 69 00 76 00 6e 00 76 00 63 00 6e 00 6d 00 } //1 wepoeoifivnvcnm
		$a_01_2 = {61 00 73 00 64 00 73 00 64 00 66 00 66 00 67 00 6a 00 6b 00 75 00 6f 00 75 00 79 00 74 00 74 00 72 00 65 00 65 00 72 00 77 00 } //1 asdsdffgjkuouyttreerw
		$a_01_3 = {54 6f 49 6e 74 65 67 65 72 } //1 ToInteger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
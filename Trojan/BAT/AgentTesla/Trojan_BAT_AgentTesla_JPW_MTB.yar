
rule Trojan_BAT_AgentTesla_JPW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_1 = {46 69 6e 64 52 64 61 73 64 73 65 73 6f 75 72 63 65 } //1 FindRdasdsesource
		$a_01_2 = {67 66 68 68 66 68 66 68 66 68 66 68 66 68 66 68 66 68 66 68 66 68 66 68 } //1 gfhhfhfhfhfhfhfhfhfhfhfh
		$a_01_3 = {67 66 64 66 66 66 66 66 66 67 } //1 gfdffffffg
		$a_01_4 = {66 73 64 66 73 64 66 73 64 } //1 fsdfsdfsd
		$a_01_5 = {23 66 73 64 66 64 73 66 2e 64 6c 6c 23 } //1 #fsdfdsf.dll#
		$a_01_6 = {23 66 73 64 66 73 64 2e 64 6c 6c 23 } //1 #fsdfsd.dll#
		$a_01_7 = {23 67 64 66 67 23 } //1 #gdfg#
		$a_01_8 = {23 67 68 66 68 2e 64 6c 6c 23 } //1 #ghfh.dll#
		$a_01_9 = {23 66 73 64 2e 64 6c 6c 23 } //1 #fsd.dll#
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
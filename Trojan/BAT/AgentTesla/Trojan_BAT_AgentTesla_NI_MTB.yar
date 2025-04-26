
rule Trojan_BAT_AgentTesla_NI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {66 61 63 65 62 6f 6f 6b 5f 63 69 72 63 6c 65 5f 35 31 32 } //1 facebook_circle_512
		$a_81_1 = {67 6d 61 69 6c 5f 74 72 61 63 6b 69 6e 67 5f 33 30 30 78 33 30 30 } //1 gmail_tracking_300x300
		$a_81_2 = {53 74 75 62 36 32 2e 52 65 73 6f 75 72 63 65 73 } //1 Stub62.Resources
		$a_81_3 = {41 62 6f 75 74 5f 4d 65 } //1 About_Me
		$a_81_4 = {50 72 61 6e 65 65 74 68 6d 61 64 75 73 68 40 67 6d 61 69 6c 2e 63 6f 6d } //1 Praneethmadush@gmail.com
		$a_81_5 = {41 73 73 32 } //1 Ass2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b1 00 00 00 13 00 00 00 0f 01 00 00 fe 03 00 00 29 01 00 00 62 01 00 00 f7 04 00 00 01 } //1
		$a_01_1 = {53 61 6c 65 73 5f 44 61 73 68 62 6f 61 72 64 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 Sales_Dashboard.Resources.resource
		$a_01_2 = {35 31 62 39 62 62 35 39 2d 33 35 38 32 2d 34 63 32 32 2d 38 36 31 30 2d 64 64 39 61 35 62 32 63 65 30 31 30 } //1 51b9bb59-3582-4c22-8610-dd9a5b2ce010
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
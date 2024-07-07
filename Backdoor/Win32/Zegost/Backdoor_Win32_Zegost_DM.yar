
rule Backdoor_Win32_Zegost_DM{
	meta:
		description = "Backdoor:Win32/Zegost.DM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 63 68 6f 73 74 2e 65 78 65 00 } //1
		$a_01_1 = {5c 53 74 61 72 74 75 70 5c 73 65 72 76 65 72 2e 65 78 65 00 } //1
		$a_01_2 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00 } //1
		$a_01_3 = {0f bc c1 d2 ec f7 d3 0f c8 b7 8c 0f ba f0 ed } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5) >=8
 
}
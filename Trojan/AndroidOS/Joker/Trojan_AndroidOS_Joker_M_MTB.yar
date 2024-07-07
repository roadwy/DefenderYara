
rule Trojan_AndroidOS_Joker_M_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 73 73 31 2e 6d 6f 62 69 6c 65 6c 69 66 65 2e 63 6f 2e 74 68 } //2 ://ss1.mobilelife.co.th
		$a_01_1 = {63 6f 6e 66 69 72 6d 4f 74 70 } //1 confirmOtp
		$a_01_2 = {2f 6f 70 2f 70 61 69 72 3f 72 65 6d 6f 74 65 3d } //1 /op/pair?remote=
		$a_01_3 = {6c 6f 61 64 43 6c 61 73 73 } //1 loadClass
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
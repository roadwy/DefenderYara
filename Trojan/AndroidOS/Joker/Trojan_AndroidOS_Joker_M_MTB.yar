
rule Trojan_AndroidOS_Joker_M_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 73 73 31 2e 6d 6f 62 69 6c 65 6c 69 66 65 2e 63 6f 2e 74 68 } //01 00  ://ss1.mobilelife.co.th
		$a_01_1 = {63 6f 6e 66 69 72 6d 4f 74 70 } //01 00  confirmOtp
		$a_01_2 = {2f 6f 70 2f 70 61 69 72 3f 72 65 6d 6f 74 65 3d } //01 00  /op/pair?remote=
		$a_01_3 = {6c 6f 61 64 43 6c 61 73 73 } //00 00  loadClass
	condition:
		any of ($a_*)
 
}
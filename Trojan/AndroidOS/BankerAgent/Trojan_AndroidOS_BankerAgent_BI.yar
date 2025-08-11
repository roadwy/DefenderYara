
rule Trojan_AndroidOS_BankerAgent_BI{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.BI,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 61 6e 67 65 53 6d 73 44 65 66 61 75 6c 74 41 70 70 41 63 74 69 76 69 74 79 } //2 ChangeSmsDefaultAppActivity
		$a_01_1 = {46 69 74 6e 65 73 73 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //2 FitnessAccessibilityService
		$a_01_2 = {55 73 65 72 50 72 65 73 65 6e 74 52 65 63 65 69 76 65 72 53 65 72 76 69 63 65 } //2 UserPresentReceiverService
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}
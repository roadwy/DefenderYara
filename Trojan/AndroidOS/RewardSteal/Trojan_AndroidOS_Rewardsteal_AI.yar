
rule Trojan_AndroidOS_Rewardsteal_AI{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AI,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 74 65 72 20 59 65 61 72 73 20 55 70 74 6f 20 32 30 33 33 } //2 Enter Years Upto 2033
		$a_01_1 = {68 64 66 63 6f 66 66 65 72 73 73 2f 48 6f 6d 65 41 63 74 69 76 69 74 79 } //2 hdfcofferss/HomeActivity
		$a_01_2 = {45 6e 74 65 72 20 4d 6f 6e 74 68 20 46 72 6f 6d 20 30 31 2d 31 32 } //2 Enter Month From 01-12
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
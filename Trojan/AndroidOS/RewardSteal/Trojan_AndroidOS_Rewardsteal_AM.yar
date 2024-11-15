
rule Trojan_AndroidOS_Rewardsteal_AM{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AM,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 72 65 6e 64 65 72 2e 63 6f 6d 2f 64 61 74 61 43 } //2 onrender.com/dataC
		$a_01_1 = {50 6f 73 74 44 61 74 61 4e 6f 64 65 43 61 72 64 } //2 PostDataNodeCard
		$a_01_2 = {43 68 65 63 6b 5f 69 66 5f 69 6e 74 65 72 6e 65 74 5f 73 69 6d 70 6c 65 } //2 Check_if_internet_simple
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
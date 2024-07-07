
rule Trojan_AndroidOS_Savesteal_GV_MTB{
	meta:
		description = "Trojan:AndroidOS/Savesteal.GV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 65 74 65 72 6e 69 74 79 2f 73 61 76 65 64 61 74 61 67 67 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //2 com/eternity/savedatagg/MainActivity
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 65 74 65 72 6e 69 74 79 70 72 2e 6e 65 74 2f 61 70 69 2f 61 63 63 6f 75 6e 74 73 } //2 https://eternitypr.net/api/accounts
		$a_00_2 = {2f 41 6e 64 72 6f 69 64 2f 64 61 74 61 2f 63 6f 6d 2e 72 74 73 6f 66 74 2e 67 72 6f 77 74 6f 70 69 61 2f 66 69 6c 65 73 2f 73 61 76 65 2e 64 61 74 } //2 /Android/data/com.rtsoft.growtopia/files/save.dat
		$a_00_3 = {61 6c 6c 6d 61 63 73 } //1 allmacs
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=7
 
}
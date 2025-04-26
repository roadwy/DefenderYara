
rule Trojan_AndroidOS_Rewardsteal_W{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.W,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 75 6e 70 6c 75 6d 62 2d 71 75 61 72 74 65 72 73 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d } //1 https://unplumb-quarters.000webhostapp.com
		$a_01_1 = {4d 79 5f 41 70 70 6c 69 63 61 74 69 6f 6e 2e 61 70 70 2e 6d 61 69 6e } //1 My_Application.app.main
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 53 4d 53 21 } //1 Failed to read SMS!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
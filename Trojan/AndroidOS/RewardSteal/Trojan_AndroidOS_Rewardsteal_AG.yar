
rule Trojan_AndroidOS_Rewardsteal_AG{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AG,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 68 69 73 61 75 62 2f 4d 79 44 65 76 69 63 65 41 64 6d 69 6e 52 65 63 65 69 76 65 72 } //2 thisaub/MyDeviceAdminReceiver
		$a_01_1 = {4f 6e 6c 79 20 31 30 20 64 69 67 69 74 20 6f 66 20 70 68 6f 6e 65 20 6e 75 6d 62 65 72 20 61 72 65 20 61 6c 6c 6f 77 65 64 20 21 } //2 Only 10 digit of phone number are allowed !
		$a_01_2 = {4f 6e 6c 79 20 32 20 63 68 61 72 65 63 74 6f 72 73 20 61 72 65 20 61 6c 6c 6f 77 65 64 20 21 } //2 Only 2 charectors are allowed !
		$a_01_3 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 68 69 64 65 20 61 70 70 20 69 63 6f 6e 3a } //2 Attempting to hide app icon:
		$a_01_4 = {63 6f 6d 70 6c 61 69 6e 73 6f 6c 75 74 69 6f 6e 73 2e 69 6e 2f } //2 complainsolutions.in/
		$a_01_5 = {41 6e 64 72 6f 69 64 20 73 65 63 75 72 69 74 79 20 73 65 72 76 69 63 65 20 61 72 65 20 72 75 6e 6e 69 6e 67 } //2 Android security service are running
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=4
 
}
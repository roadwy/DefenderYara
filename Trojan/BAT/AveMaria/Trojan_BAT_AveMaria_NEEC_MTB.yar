
rule Trojan_BAT_AveMaria_NEEC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 62 66 66 32 61 37 31 2d 37 64 62 36 2d 34 32 34 33 2d 38 61 63 62 2d 64 33 38 63 33 32 62 63 33 31 30 64 } //5 bbff2a71-7db6-4243-8acb-d38c32bc310d
		$a_01_1 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //5 kLjw4iIsCLsZtxc4lksN0j
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 44 00 61 00 74 00 61 00 43 00 2e 00 65 00 78 00 65 00 } //5 WindowsDataC.exe
		$a_01_3 = {6d 69 6e 69 20 63 61 6c 63 75 6c 61 74 6f 72 2e 65 78 65 } //2 mini calculator.exe
		$a_01_4 = {6d 69 6e 69 5f 63 61 6c 63 75 6c 61 74 6f 72 2e 4d 79 } //2 mini_calculator.My
		$a_01_5 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_6 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=21
 
}

rule Backdoor_Win32_Zacom_A{
	meta:
		description = "Backdoor:Win32/Zacom.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {89 45 e0 2b 85 cc d6 ff ff 89 45 e4 3d 40 77 1b 00 0f 83 e2 00 00 00 } //2
		$a_01_1 = {2e 61 73 70 3f 48 6f 73 74 49 44 3d 00 } //1
		$a_01_2 = {47 6f 6f 67 6c 65 5a 43 4d 00 } //1 潇杯敬䍚M
		$a_01_3 = {47 41 50 5a 43 4d 5f 4d 41 49 4e 45 58 45 00 } //1
		$a_01_4 = {53 54 54 69 70 2e 61 73 70 00 } //1
		$a_01_5 = {49 49 53 00 47 45 54 00 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00 } //1
		$a_01_6 = {3d 04 10 00 00 77 23 74 1a 2d 04 0c 00 00 74 0c 83 e8 05 75 23 bf } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
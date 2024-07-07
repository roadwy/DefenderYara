
rule Backdoor_Win32_Trogbot_C{
	meta:
		description = "Backdoor:Win32/Trogbot.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0e 33 c8 81 e1 ff 00 00 00 c1 e8 08 33 04 8d 90 01 04 46 83 ef 01 75 e5 90 00 } //2
		$a_01_1 = {47 65 74 53 54 50 72 6f 78 79 46 72 6f 6d 52 65 67 3a 20 } //1 GetSTProxyFromReg: 
		$a_01_2 = {63 68 61 6c 6c 65 6e 67 65 00 00 00 63 68 61 6e 67 65 64 69 64 00 } //1
		$a_03_3 = {47 6c 6f 62 61 6c 5c 7b 90 01 24 7d 00 00 00 7a 63 2e 6c 6f 67 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}

rule Backdoor_Win32_PcClient_BA{
	meta:
		description = "Backdoor:Win32/PcClient.BA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 cf 01 00 40 6a 00 8d 8c 24 08 01 00 00 6a 01 51 ff 15 4c 20 00 10 85 c0 74 07 50 ff 15 48 20 00 10 } //1
		$a_01_1 = {2e 64 6c 6c 00 53 4b 00 00 } //1
		$a_01_2 = {4f 70 65 6e 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e 41 } //1 OpenWindowStationA
		$a_01_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
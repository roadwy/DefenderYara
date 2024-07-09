
rule Trojan_Win32_Thunmal_A{
	meta:
		description = "Trojan:Win32/Thunmal.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 6f 57 2e 63 6f 6d 20 41 63 63 6f 75 6e 74 2f 50 61 73 73 77 6f 72 64 20 52 65 74 72 69 65 76 61 6c } //10 WoW.com Account/Password Retrieval
		$a_00_1 = {68 74 74 70 3a 2f 2f 25 73 3f 75 3d 25 73 26 6d 3d 25 73 26 61 63 74 69 6f 6e 3d 66 69 6e 64 } //10 http://%s?u=%s&m=%s&action=find
		$a_02_2 = {63 3a 5c 70 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 54 68 75 6e 4d 61 69 6c 5c [0-08] 2e 65 78 65 } //10
		$a_00_3 = {5a 77 44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 46 69 6c 65 } //1 ZwDeviceIoControlFile
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1) >=30
 
}
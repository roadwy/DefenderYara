
rule TrojanSpy_Win32_Keylogger_FX{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00 } //1
		$a_00_1 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 63 75 72 72 65 6e 74 70 72 6f 66 69 6c 65 20 73 74 61 74 65 20 6f 66 66 } //1 netsh advfirewall set currentprofile state off
		$a_00_2 = {3c 63 74 72 6c 3e 00 } //1
		$a_00_3 = {57 4e 44 4d 20 4e 4f 54 20 43 52 45 41 54 45 44 00 } //1
		$a_03_4 = {83 ec 04 66 3d 01 80 0f 85 df 03 00 00 66 83 bd b2 fd ff ff 26 7e 48 66 83 bd b2 fd ff ff 40 7f 3e 0f bf 85 b2 fd ff ff 89 44 24 08 90 01 08 8d 85 b8 fe ff ff 89 04 24 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
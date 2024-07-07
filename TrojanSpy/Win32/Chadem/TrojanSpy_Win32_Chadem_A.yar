
rule TrojanSpy_Win32_Chadem_A{
	meta:
		description = "TrojanSpy:Win32/Chadem.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 ff d6 66 3d 15 00 0f 85 90 01 02 00 00 8b 15 90 01 04 6a 02 90 00 } //1
		$a_01_1 = {8d 44 24 18 50 68 01 00 00 98 56 } //1
		$a_01_2 = {64 6d 3d 25 73 26 6c 67 3d 25 73 26 70 73 3d 25 73 } //1 dm=%s&lg=%s&ps=%s
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}

rule TrojanSpy_Win32_Binal_A{
	meta:
		description = "TrojanSpy:Win32/Binal.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8a 5c 30 ff 8b c3 04 d8 3c 57 77 0a 83 e0 7f 0f } //10
		$a_03_1 = {8a 12 80 ea 41 8d 14 92 8d 14 92 8b 4d 90 01 01 8a 49 01 80 e9 41 02 d1 8b ce 2a d1 8b cf 2a d1 90 00 } //10
		$a_03_2 = {66 81 3b 4d 5a 0f 85 90 01 02 00 00 90 02 40 81 3f 50 45 00 00 0f 85 90 01 02 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1) >=11
 
}
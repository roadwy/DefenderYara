
rule TrojanDropper_Win32_Kanav_A{
	meta:
		description = "TrojanDropper:Win32/Kanav.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c3 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 68 90 01 04 ff 15 90 00 } //1
		$a_01_1 = {c0 e1 04 02 cb 8a 9c 24 1c 08 00 00 32 cb 45 88 4c 34 10 8b fa 83 c9 ff 33 c0 46 f2 ae f7 d1 49 3b f1 } //1
		$a_00_2 = {38 31 41 36 41 38 44 32 30 43 41 32 41 45 } //1 81A6A8D20CA2AE
		$a_00_3 = {46 69 6e 64 52 65 73 6f 75 72 63 65 20 65 72 72 6f 72 20 69 73 20 30 78 25 30 38 78 } //1 FindResource error is 0x%08x
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
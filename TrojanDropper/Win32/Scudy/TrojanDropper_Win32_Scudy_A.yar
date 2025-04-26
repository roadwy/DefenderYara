
rule TrojanDropper_Win32_Scudy_A{
	meta:
		description = "TrojanDropper:Win32/Scudy.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 07 32 18 83 c0 04 88 5c 28 fc 8a 1c 0a 32 58 fd 83 c1 04 88 59 fc 8a 58 fe 32 5e ff 83 c6 04 88 59 fd 8a 58 ff 32 5e fc 88 59 fe } //1
		$a_01_1 = {45 6e 75 6d 52 65 73 4e 61 6d 65 50 72 6f 63 3a 3a 46 69 6e 64 52 65 73 6f 75 72 63 65 } //1 EnumResNameProc::FindResource
		$a_01_2 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //1 ShowSuperHidden
		$a_01_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
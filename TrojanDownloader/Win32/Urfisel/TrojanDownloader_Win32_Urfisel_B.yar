
rule TrojanDownloader_Win32_Urfisel_B{
	meta:
		description = "TrojanDownloader:Win32/Urfisel.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f 01 e2 c1 ea 18 02 d0 8d 35 } //1
		$a_01_1 = {ac 2a c2 32 c2 aa e2 f8 } //1
		$a_03_2 = {51 57 53 ff 15 90 01 04 85 c0 75 04 c9 c2 10 00 89 06 83 c6 04 33 c0 33 c9 49 f2 ae 59 e2 e0 90 00 } //1
		$a_01_3 = {74 32 66 81 fb 4d 5a 75 c3 33 c0 68 } //1
		$a_01_4 = {81 3e 68 74 74 70 75 03 8d 76 07 81 3e 77 77 77 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}

rule TrojanDownloader_Win32_Zlob_gen_CK{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {20 4e 41 56 20 67 75 79 73 } //1  NAV guys
		$a_01_1 = {56 43 32 30 58 43 30 30 } //1 VC20XC00
		$a_01_2 = {4e 61 6d 32 } //1 Nam2
		$a_01_3 = {49 45 56 55 } //1 IEVU
		$a_03_4 = {c1 ee 02 46 [0-02] 28 61 5b 02 } //3
		$a_00_5 = {8a 14 01 32 54 24 24 88 10 48 ff 4c 24 10 75 f0 } //3
		$a_00_6 = {8a 04 0a 32 44 24 20 88 01 49 ff 4c 24 10 75 f0 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*3+(#a_00_5  & 1)*3+(#a_00_6  & 1)*3) >=4
 
}
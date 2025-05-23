
rule PWS_Win32_Cimuz_E{
	meta:
		description = "PWS:Win32/Cimuz.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {74 12 6a 00 6a 01 5f 57 ff 35 ?? ?? 00 10 ff d3 85 c0 75 } //1
		$a_03_1 = {8b 7d 3c 03 fd 81 3f 50 45 00 00 0f 85 0e 01 00 00 8b 35 ?? ?? 00 10 6a 04 68 00 20 00 00 ff 77 50 ff 77 34 ff d6 8b d8 85 db } //1
		$a_03_2 = {8b 43 0c 03 44 24 10 50 ff 15 ?? ?? 00 10 83 f8 ff } //1
		$a_03_3 = {8d 04 77 f7 c1 00 00 00 04 8d 04 42 8b 34 85 ?? ?? 00 10 74 06 81 ce 00 02 00 00 } //1
		$a_03_4 = {99 5b f7 fb 30 14 90 04 01 02 31 39 41 3b 90 04 01 02 cf ce 72 f0 90 09 04 00 8b c1 6a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}
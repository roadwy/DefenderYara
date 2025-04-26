
rule Spammer_Win32_Rlsloup_B{
	meta:
		description = "Spammer:Win32/Rlsloup.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 f8 72 59 75 6a 0f be 44 3e 01 50 e8 ?? ?? 00 00 83 f8 63 59 75 59 0f be 44 3e 02 50 e8 ?? ?? 00 00 83 f8 70 } //1
		$a_01_1 = {c7 06 ff d8 ff e0 8d 46 04 c7 00 00 10 4a 46 83 c0 04 c7 00 49 46 00 01 89 48 04 } //1
		$a_01_2 = {74 16 8b 44 24 0c 8b 4c 24 04 8a 11 f6 d2 88 10 40 41 ff 4c 24 08 75 f2 } //1
		$a_00_3 = {2f 62 6e 2f 63 6f 6d 67 61 74 65 2e 78 68 74 6d 6c 3f } //1 /bn/comgate.xhtml?
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}
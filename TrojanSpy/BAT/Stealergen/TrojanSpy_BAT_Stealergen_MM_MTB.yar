
rule TrojanSpy_BAT_Stealergen_MM_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {73 31 01 00 0a 0a 73 31 01 00 0a 0b 06 72 a9 18 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 20 f4 01 00 00 28 ?? ?? ?? 0a 00 07 72 50 19 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 08 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 04 11 04 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 05 11 05 11 04 17 8d 19 00 00 01 25 16 09 a2 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 } //1
		$a_03_1 = {6c 00 6c 00 64 00 2e 00 [0-60] 2f 00 73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 6d 00 6f 00 63 00 2e 00 70 00 70 00 61 00 64 00 72 00 6f 00 63 00 73 00 69 00 64 00 2e 00 6e 00 64 00 63 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00 } //1
		$a_01_2 = {65 00 68 00 65 00 79 00 67 00 75 00 79 00 73 00 73 00 73 00 } //1 eheyguysss
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 } //1 Create__Instance
		$a_01_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e } //1 DebuggerHidden
		$a_01_7 = {67 65 74 5f 70 61 73 73 77 64 } //1 get_passwd
		$a_01_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_9 = {6c 6f 67 69 6e 5f 4c 6f 61 64 } //1 login_Load
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
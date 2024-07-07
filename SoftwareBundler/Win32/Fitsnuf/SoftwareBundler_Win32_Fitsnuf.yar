
rule SoftwareBundler_Win32_Fitsnuf{
	meta:
		description = "SoftwareBundler:Win32/Fitsnuf,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 6e 73 74 69 66 66 2e 70 77 } //10 http://unstiff.pw
		$a_01_1 = {57 61 6a 49 45 6e 68 61 6e 63 65 } //1 WajIEnhance
		$a_01_2 = {73 6f 63 69 61 6c 32 73 65 61 72 63 68 2e 65 78 65 } //1 social2search.exe
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 79 65 73 73 65 61 72 63 68 65 73 53 6f 66 74 77 61 72 65 } //1 SOFTWARE\yessearchesSoftware
		$a_01_4 = {79 65 73 73 65 61 72 63 68 65 73 68 70 } //1 yessearcheshp
		$a_01_5 = {5c 73 74 75 62 5f 79 6f 75 6e 64 6f 6f 2e 65 78 65 } //1 \stub_youndoo.exe
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 79 6f 75 6e 64 6f 6f 53 6f 66 74 77 61 72 65 } //1 SOFTWARE\youndooSoftware
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=12
 
}

rule SoftwareBundler_Win32_Techrelinst{
	meta:
		description = "SoftwareBundler:Win32/Techrelinst,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 20 59 6f 75 72 20 55 70 64 61 74 65 72 20 74 68 65 20 64 65 66 61 75 6c 74 20 64 69 72 65 63 74 6f 72 79 2e } //1 Install Your Updater the default directory.
		$a_01_1 = {49 6e 73 74 61 6c 6c 20 4f 70 65 6e 20 44 6f 77 6e 6c 6f 61 64 20 4d 61 6e 61 67 65 72 20 74 6f 20 74 68 65 20 64 65 66 61 75 6c 74 20 64 69 72 65 63 74 6f 72 79 2e } //1 Install Open Download Manager to the default directory.
		$a_01_2 = {4f 70 65 6e 20 68 74 74 70 3a 2f 2f 77 77 77 2e 53 6f 63 69 61 6c 32 53 65 61 72 63 68 2e 63 6f 6d 2f 70 72 69 76 61 63 79 } //10 Open http://www.Social2Search.com/privacy
		$a_01_3 = {65 6e 61 62 6c 65 20 53 6f 63 69 61 6c 32 53 65 61 72 63 68 20 66 6f 72 20 61 6c 6c 20 62 72 6f 77 73 65 72 73 2e } //10 enable Social2Search for all browsers.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=21
 
}
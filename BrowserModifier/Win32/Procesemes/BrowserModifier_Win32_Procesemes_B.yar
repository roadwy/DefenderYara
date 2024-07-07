
rule BrowserModifier_Win32_Procesemes_B{
	meta:
		description = "BrowserModifier:Win32/Procesemes.B,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
		$a_01_2 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 57 } //1 HttpOpenRequestW
		$a_01_3 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 36 00 2e 00 30 00 62 00 3b 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 35 00 2e 00 30 00 3b 00 20 00 2e 00 4e 00 45 00 54 00 20 00 43 00 4c 00 52 00 20 00 31 00 2e 00 30 00 2e 00 32 00 39 00 31 00 34 00 29 00 } //1 Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.2914)
		$a_01_4 = {49 6e 74 65 72 6e 65 74 53 65 74 43 6f 6f 6b 69 65 57 } //1 InternetSetCookieW
		$a_01_5 = {8b d7 83 e2 01 c1 e2 02 6a 04 59 2b ca d2 e0 08 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
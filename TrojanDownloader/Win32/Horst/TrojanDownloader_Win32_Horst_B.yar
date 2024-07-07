
rule TrojanDownloader_Win32_Horst_B{
	meta:
		description = "TrojanDownloader:Win32/Horst.B,SIGNATURE_TYPE_PEHSTR,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //1 Microsoft Visual C++ Runtime Library
		$a_01_1 = {25 73 20 2b 20 43 52 41 43 4b 20 2b 20 41 43 54 49 56 41 54 4f 52 2e 45 58 45 } //1 %s + CRACK + ACTIVATOR.EXE
		$a_01_2 = {25 73 20 2b 20 43 52 41 43 4b 20 2b 20 4e 4f 43 44 2e 65 78 65 } //1 %s + CRACK + NOCD.exe
		$a_01_3 = {25 73 20 2d 20 4e 6f 43 44 20 43 72 61 63 6b 20 4b 65 79 47 65 6e 2e 65 78 65 } //1 %s - NoCD Crack KeyGen.exe
		$a_01_4 = {62 61 63 6b 2e 68 61 73 74 65 6d 61 6e 2e 63 6f 6d } //1 back.hasteman.com
		$a_01_5 = {61 64 73 2e 7a 61 62 6c 65 6e 2e 63 6f 6d } //1 ads.zablen.com
		$a_01_6 = {72 65 6c 2e 73 74 61 74 61 64 64 2e 63 6f 6d 2f 64 2f 64 6e 2f 64 6c 6c 2f 7a 6c 69 62 31 2e 64 6c 6c } //1 rel.statadd.com/d/dn/dll/zlib1.dll
		$a_01_7 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}
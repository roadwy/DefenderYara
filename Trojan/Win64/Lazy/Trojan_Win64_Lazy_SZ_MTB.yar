
rule Trojan_Win64_Lazy_SZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 69 6e 67 20 42 6c 6f 63 6b 65 72 3a 20 } //1 Loading Blocker: 
		$a_01_1 = {43 6c 6f 73 65 20 4d 6f 64 65 72 6e 20 57 61 72 66 61 72 65 20 42 65 66 6f 72 65 20 59 6f 75 20 4c 6f 61 64 20 54 68 65 20 44 72 69 76 65 72 } //1 Close Modern Warfare Before You Load The Driver
		$a_01_2 = {4c 6f 61 64 65 72 2e 70 64 62 } //1 Loader.pdb
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 64 6e 53 70 79 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq dnSpy.exe
		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 48 54 54 50 44 65 62 75 67 67 65 72 55 49 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq HTTPDebuggerUI.exe
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 69 64 61 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq ida.exe
		$a_01_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_7 = {42 6c 6f 63 6b 65 72 20 49 6e 6a 65 63 74 6f 72 31 } //1 Blocker Injector1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
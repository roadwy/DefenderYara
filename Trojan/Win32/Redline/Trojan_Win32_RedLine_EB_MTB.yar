
rule Trojan_Win32_RedLine_EB_MTB{
	meta:
		description = "Trojan:Win32/RedLine.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 4f 6a 69 63 67 55 64 39 58 45 6d 39 39 38 50 31 41 36 6d 6b 74 31 53 6f 51 51 6a 79 70 72 6b 4f 62 38 44 4c 4e 7a 71 71 35 67 67 4c 49 30 51 79 4e 37 6d 70 79 52 71 47 4c 6b 49 36 6d 38 54 30 } //1 HOjicgUd9XEm998P1A6mkt1SoQQjyprkOb8DLNzqq5ggLI0QyN7mpyRqGLkI6m8T0
		$a_01_1 = {66 59 68 61 63 4c 36 68 59 6c 56 5a 77 50 6b 67 58 47 46 34 49 75 6a 33 59 6f 6f 77 37 65 57 57 46 76 53 73 65 48 69 47 34 30 49 6b 78 47 41 68 65 71 50 41 63 76 30 6b 78 50 6e 30 75 37 45 48 36 } //1 fYhacL6hYlVZwPkgXGF4Iuj3Yoow7eWWFvSseHiG40IkxGAheqPAcv0kxPn0u7EH6
		$a_01_2 = {2f 64 65 61 63 74 69 76 61 74 65 } //1 /deactivate
		$a_01_3 = {41 63 74 69 76 61 74 69 6f 6e 31 33 30 37 32 32 38 33 30 36 } //1 Activation1307228306
		$a_01_4 = {65 00 76 00 71 00 77 00 65 00 71 00 77 00 65 00 } //1 evqweqwe
		$a_01_5 = {53 00 79 00 73 00 74 00 65 00 6d 00 42 00 69 00 6f 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //1 SystemBiosVersion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
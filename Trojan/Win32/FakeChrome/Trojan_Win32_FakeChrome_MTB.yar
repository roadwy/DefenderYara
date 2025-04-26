
rule Trojan_Win32_FakeChrome_MTB{
	meta:
		description = "Trojan:Win32/FakeChrome!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {47 6f 6f 67 6c 65 43 68 72 6f 6d 65 2d [0-05] 2e 65 78 65 } //1
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 43 69 74 72 69 78 5c 44 61 7a 7a 6c 65 } //Software\Citrix\Dazzle  1
		$a_80_2 = {49 43 41 20 43 6c 69 65 6e 74 5c 53 65 6c 66 53 65 72 76 69 63 65 50 6c 75 67 69 6e 5c 53 65 6c 66 53 65 72 76 69 63 65 2e 65 78 65 } //ICA Client\SelfServicePlugin\SelfService.exe  1
		$a_02_3 = {74 00 64 00 6c 00 31 00 [0-10] 2d 00 [0-20] 40 00 40 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 2e 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}
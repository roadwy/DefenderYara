
rule Trojan_Win32_OffLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65 00 } //1 \\server\share
		$a_01_1 = {65 00 73 00 73 00 2e 00 66 00 6f 00 6f 00 64 00 63 00 72 00 69 00 62 00 2e 00 73 00 69 00 74 00 65 } //1
		$a_01_2 = {77 00 77 00 2e 00 70 00 68 00 70 } //1
		$a_01_3 = {54 55 4e 49 4e 53 54 41 4c 4c 50 52 4f 47 52 45 53 53 46 4f 52 4d } //1 TUNINSTALLPROGRESSFORM
		$a_01_4 = {54 44 4f 57 4e 4c 4f 41 44 57 49 5a 41 52 44 50 41 47 45 } //1 TDOWNLOADWIZARDPAGE
		$a_01_5 = {44 4f 57 4e 4c 4f 41 44 54 45 4d 50 4f 52 41 52 59 46 49 4c 45 } //1 DOWNLOADTEMPORARYFILE
		$a_01_6 = {54 4f 4e 44 4f 57 4e 4c 4f 41 44 50 52 4f 47 52 45 53 53 } //1 TONDOWNLOADPROGRESS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
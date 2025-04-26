
rule Trojan_Win32_LummaStealerClick_A_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 28 00 24 00 } //1 -split ($
		$a_00_2 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 28 00 } //1 .CreateDecryptor(
		$a_00_3 = {2d 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //1 -replace
		$a_00_4 = {2e 00 53 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //1 .Substring(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
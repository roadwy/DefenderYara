
rule Trojan_Win32_Amadey_ZAC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ZAC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3a 00 3a 00 47 00 65 00 74 00 54 00 6f 00 74 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 28 00 24 00 } //1 ::GetTotalMemory($
		$a_00_1 = {2e 00 52 00 65 00 61 00 44 00 54 00 4f 00 65 00 4e 00 64 00 28 00 } //1 .ReaDTOeNd(
		$a_00_2 = {66 00 72 00 6f 00 4d 00 42 00 41 00 53 00 45 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 47 00 28 00 } //1 froMBASE64strinG(
		$a_00_3 = {2d 00 6a 00 6f 00 69 00 6e 00 } //1 -join
		$a_00_4 = {63 00 68 00 61 00 72 00 5b 00 5d 00 } //1 char[]
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
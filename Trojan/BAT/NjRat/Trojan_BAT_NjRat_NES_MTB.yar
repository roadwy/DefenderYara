
rule Trojan_BAT_NjRat_NES_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_03_0 = {7e 3e 00 00 04 ?? ?? ?? 01 00 00 59 97 29 19 00 00 11 02 50 6f 8b 00 00 0a 2a } //5
		$a_01_1 = {44 69 73 63 6f 72 64 } //4 Discord
		$a_01_2 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //4 NtSetInformationProcess
		$a_01_3 = {73 65 74 5f 4d 69 6e 57 6f 72 6b 69 6e 67 53 65 74 } //4 set_MinWorkingSet
		$a_01_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //4 set_UseShellExecute
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=21
 
}
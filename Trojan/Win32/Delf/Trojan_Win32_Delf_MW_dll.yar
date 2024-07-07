
rule Trojan_Win32_Delf_MW_dll{
	meta:
		description = "Trojan:Win32/Delf.MW!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {05 00 00 00 2e 6c 69 6e 6b } //1
		$a_02_1 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 54 54 50 6c 61 79 65 72 00 00 00 90 02 10 54 50 6c 61 79 65 72 2e 65 78 65 00 90 00 } //1
		$a_00_2 = {43 72 65 61 74 65 46 61 63 74 6f 72 79 73 } //1 CreateFactorys
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
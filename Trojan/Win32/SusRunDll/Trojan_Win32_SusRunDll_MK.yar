
rule Trojan_Win32_SusRunDll_MK{
	meta:
		description = "Trojan:Win32/SusRunDll.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //1 rundll32
		$a_00_1 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 } //1 phonehome
		$a_00_2 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 5f 00 6d 00 61 00 69 00 6e 00 } //1 phonehome_main
		$a_00_3 = {61 00 61 00 30 00 36 00 65 00 33 00 39 00 65 00 2d 00 37 00 38 00 37 00 36 00 2d 00 34 00 62 00 61 00 33 00 2d 00 62 00 65 00 65 00 65 00 2d 00 34 00 32 00 62 00 64 00 38 00 30 00 66 00 66 00 33 00 36 00 32 00 65 00 } //-1 aa06e39e-7876-4ba3-beee-42bd80ff362e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}
rule Trojan_Win32_SusRunDll_MK_2{
	meta:
		description = "Trojan:Win32/SusRunDll.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //1 rundll32
		$a_00_1 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 } //1 phonehome
		$a_00_2 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 5f 00 6d 00 61 00 69 00 6e 00 } //1 phonehome_main
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
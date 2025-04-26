
rule Trojan_Win32_GuLoader_BM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 00 6f 00 72 00 62 00 6f 00 67 00 73 00 74 00 61 00 76 00 2e 00 6c 00 6e 00 6b 00 } //1 Forbogstav.lnk
		$a_01_1 = {43 00 6f 00 70 00 79 00 20 00 44 00 65 00 74 00 61 00 69 00 6c 00 73 00 20 00 54 00 6f 00 20 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 } //1 Copy Details To Clipboard
		$a_01_2 = {2a 00 2e 00 73 00 63 00 75 00 } //1 *.scu
		$a_01_3 = {42 00 55 00 4c 00 4c 00 4e 00 45 00 43 00 4b 00 } //1 BULLNECK
		$a_01_4 = {62 00 75 00 6c 00 6b 00 6c 00 61 00 64 00 6e 00 69 00 6e 00 67 00 65 00 72 00 } //1 bulkladninger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
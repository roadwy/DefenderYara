
rule Trojan_Win32_Zenapk_CCCI_MTB{
	meta:
		description = "Trojan:Win32/Zenapk.CCCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 65 61 74 62 58 4e 64 69 76 69 64 65 64 } //1 meatbXNdivided
		$a_01_1 = {42 66 6c 79 77 69 6e 67 65 64 68 69 73 61 } //1 Bflywingedhisa
		$a_01_2 = {56 66 69 73 68 67 69 76 65 6e 66 70 48 6d 6f 76 65 64 } //1 VfishgivenfpHmoved
		$a_01_3 = {61 62 6f 76 65 53 74 68 65 72 65 78 } //1 aboveStherex
		$a_01_4 = {73 61 79 69 6e 67 6d 65 61 74 69 74 73 65 6c 66 } //1 sayingmeatitself
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}

rule Trojan_Win32_Swisyn_E{
	meta:
		description = "Trojan:Win32/Swisyn.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 6d 61 67 65 6e 74 73 2e 65 78 65 00 } //1
		$a_01_1 = {70 61 73 73 65 73 2e 78 6d 00 } //1 慰獳獥砮m
		$a_01_2 = {2f 67 74 2e 70 68 70 00 } //1
		$a_01_3 = {2a 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 2a 00 } //1 椪瑮牥敮⁴硥汰牯牥*
		$a_01_4 = {6b 65 79 6c 6f 67 2e 74 78 74 00 } //1
		$a_01_5 = {70 61 73 6c 69 73 74 2e 74 78 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
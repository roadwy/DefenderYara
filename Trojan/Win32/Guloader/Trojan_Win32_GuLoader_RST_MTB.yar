
rule Trojan_Win32_GuLoader_RST_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 6c 69 67 68 74 69 6e 67 20 72 65 64 65 73 63 72 69 62 65 73 20 6e 61 73 69 6f 69 6e 69 61 6c } //1 flighting redescribes nasioinial
		$a_81_1 = {61 75 74 6f 64 69 64 61 6b 74 65 20 6c 65 61 68 20 62 75 62 61 73 } //1 autodidakte leah bubas
		$a_81_2 = {6c 61 6d 70 61 74 69 61 } //1 lampatia
		$a_81_3 = {64 6f 76 65 74 61 69 6c 77 69 73 65 2e 65 78 65 } //1 dovetailwise.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
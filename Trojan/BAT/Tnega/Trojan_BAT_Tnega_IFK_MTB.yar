
rule Trojan_BAT_Tnega_IFK_MTB{
	meta:
		description = "Trojan:BAT/Tnega.IFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {70 70 70 68 68 79 66 2e 65 78 65 } //1 ppphhyf.exe
		$a_01_1 = {63 00 64 00 73 00 63 00 64 00 73 00 63 00 64 00 73 00 64 00 2e 00 65 00 78 00 65 00 } //1 cdscdscdsd.exe
		$a_01_2 = {5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 31 00 33 00 } //1 _ICON_1913
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_5 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_81_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_7 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}

rule Trojan_Win32_Farfli_ASDL_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 78 da 04 00 6a 00 ff 15 ?? ?? ?? 00 50 ff 15 } //2
		$a_01_1 = {33 c0 56 8b f1 57 b9 9e 36 01 00 8d 7e 10 } //1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
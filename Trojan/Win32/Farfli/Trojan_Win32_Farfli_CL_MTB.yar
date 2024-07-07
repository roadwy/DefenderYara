
rule Trojan_Win32_Farfli_CL_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8a 16 81 e1 ff 00 00 00 33 ca c1 e8 08 8b 0c 8d f8 8c 00 10 33 c1 46 4f 75 e2 } //1
		$a_01_1 = {8a 19 81 e2 ff 00 00 00 33 d3 c1 e8 08 8b 14 95 f8 8c 00 10 33 c2 41 4f 75 dd } //1
		$a_01_2 = {50 6c 75 67 69 6e 4d 65 } //1 PluginMe
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
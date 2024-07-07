
rule Trojan_Win32_Farfli_CO_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 ca 33 c1 8b 4d 08 03 4d fc 0f b6 09 2b c8 89 4d dc 8b 45 08 03 45 fc 8a 4d dc 88 08 0f b6 45 dc 89 45 f8 eb 8a } //5
		$a_01_1 = {c6 45 e4 56 c6 45 e5 69 c6 45 e6 72 c6 45 e7 74 c6 45 e8 75 c6 45 e9 61 c6 45 ea 6c c6 45 eb 50 c6 45 ec 72 c6 45 ed 6f c6 45 ee 74 c6 45 ef 65 c6 45 f0 63 c6 45 f1 74 } //5
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}
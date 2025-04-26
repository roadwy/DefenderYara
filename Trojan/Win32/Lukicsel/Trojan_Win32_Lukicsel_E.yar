
rule Trojan_Win32_Lukicsel_E{
	meta:
		description = "Trojan:Win32/Lukicsel.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {4b 85 db 7c 0f 43 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 f2 } //1
		$a_03_1 = {8b 5d f8 8b 45 f4 83 c0 34 03 d8 8d 55 f4 8b c3 b9 04 00 00 00 e8 ?? ?? ?? ?? 8b 45 f4 89 45 f0 8b 5d f8 83 ee 0a } //1
		$a_03_2 = {8b 45 f4 8b 40 08 ba ?? ?? ?? ?? 8b 08 ff 51 38 8b 45 f4 8b 40 08 ba ?? ?? ?? ?? 8b 08 ff 51 38 8b 45 f4 8b 40 08 ba ?? ?? ?? ?? 8b 08 ff 51 38 } //1
		$a_01_3 = {66 83 7b 12 00 74 0c 56 8b 4b 4c 8b d3 8b 43 14 ff 53 10 85 f6 75 0c ba 02 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
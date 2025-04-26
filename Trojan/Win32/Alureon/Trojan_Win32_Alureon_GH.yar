
rule Trojan_Win32_Alureon_GH{
	meta:
		description = "Trojan:Win32/Alureon.GH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 3b ac 33 f8 97 2b fe 88 03 8b 85 ?? ?? ?? ?? 03 c3 49 74 09 43 42 83 fa 08 75 e4 } //1
		$a_03_1 = {74 3f 89 45 b8 83 20 00 8d 55 c0 8b c8 ff 15 ?? ?? ?? ?? fa a1 6c ae 00 10 8b 0d ?? ?? ?? ?? 89 48 04 fb } //1
		$a_03_2 = {8d 7c 08 fe 6a 00 57 68 08 01 00 00 68 ?? ?? ?? ?? 68 bb 20 01 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
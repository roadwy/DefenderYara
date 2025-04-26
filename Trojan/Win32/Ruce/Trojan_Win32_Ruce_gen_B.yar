
rule Trojan_Win32_Ruce_gen_B{
	meta:
		description = "Trojan:Win32/Ruce.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b f8 83 c4 04 85 ff 75 ?? 68 20 4e 00 00 ff d3 46 83 fe 09 7c } //1
		$a_01_1 = {50 6a 00 6a 2a ff 15 } //1
		$a_03_2 = {68 00 80 00 00 68 04 01 00 00 ?? ?? ff 15 } //1
		$a_01_3 = {6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 22 20 2d 6e 6f 68 6f 6d 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
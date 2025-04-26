
rule Trojan_Win32_Koobface_gen_F{
	meta:
		description = "Trojan:Win32/Koobface.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 51 70 8b 45 ?? 3b ?? 74 0d 8b ?? 94 01 00 00 8b 08 52 50 ff 51 68 90 09 06 00 90 00 } //1
		$a_03_1 = {ff 91 e0 00 00 00 8b 45 ec (46|47) 81 90 03 01 01 fe ff 04 01 00 00 7e 0f } //1
		$a_01_2 = {49 46 45 58 49 54 00 } //1
		$a_01_3 = {42 4c 41 43 4b 4c 41 42 45 4c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
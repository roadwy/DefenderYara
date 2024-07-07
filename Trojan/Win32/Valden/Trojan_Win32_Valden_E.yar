
rule Trojan_Win32_Valden_E{
	meta:
		description = "Trojan:Win32/Valden.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 64 61 74 61 3d 69 6e 66 6f 26 62 61 6e 6b 3d 90 01 01 26 75 73 65 72 5f 6e 61 6d 65 3d 25 73 90 00 } //1
		$a_03_1 = {8b 77 3c 8d 45 90 01 01 50 6a 40 03 f7 ff 76 50 57 ff 15 90 01 04 8b 46 50 03 c7 eb 0a 8b 0f 3b 4d 0c 74 09 83 c7 04 3b f8 72 f2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
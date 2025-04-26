
rule Trojan_Win32_SamScissors_SB{
	meta:
		description = "Trojan:Win32/SamScissors.SB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 49 63 6f 6e 53 74 6f 72 61 67 65 73 2f 69 6d 61 67 65 73 2f 6d 61 69 6e 2f 69 63 6f 6e 25 64 2e 69 63 6f } //https://raw.githubusercontent.com/IconStorages/images/main/icon%d.ico  5
		$a_80_1 = {5f 5f 74 75 74 6d 61 } //__tutma  1
		$a_80_2 = {5f 5f 74 75 74 6d 63 } //__tutmc  1
		$a_03_3 = {33 c1 45 8b ca 8b c8 c1 e9 ?? 33 c1 81 c2 ?? ?? ?? ?? 8b c8 c1 e1 ?? 33 c1 41 8b c8 90 0a 1e 00 c1 e1 } //1
		$a_03_4 = {ff d5 48 85 c0 74 ?? 81 7b ?? ca 7d 0f 00 75 ?? 48 8d 54 24 ?? 48 8d 4c 24 ?? ff d0 8b f8 44 8b 44 24 ?? 4c 8d 4c 24 ?? ba 00 10 00 00 48 8b cd ff 15 90 0a 3b 00 ff 15 ?? ?? ?? ?? 85 c0 74 } //1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=8
 
}
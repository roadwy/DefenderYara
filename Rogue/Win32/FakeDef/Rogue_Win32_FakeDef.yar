
rule Rogue_Win32_FakeDef{
	meta:
		description = "Rogue:Win32/FakeDef,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3f 00 73 00 74 00 61 00 67 00 65 00 3d 00 31 00 26 00 75 00 69 00 64 00 3d 00 25 00 53 00 26 00 69 00 64 00 3d 00 25 00 64 00 26 00 73 00 75 00 62 00 69 00 64 00 3d 00 25 00 64 00 26 00 6f 00 73 00 3d 00 25 00 64 00 } //1 ?stage=1&uid=%S&id=%d&subid=%d&os=%d
		$a_03_1 = {ff 50 04 89 45 fc 83 7d fc 00 0f 84 ?? ?? 00 00 8b 45 ?? 83 c0 14 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Rogue_Win32_FakeDef_2{
	meta:
		description = "Rogue:Win32/FakeDef,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 41 00 6e 00 74 00 69 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //1 Microsoft\Microsoft Antimalware
		$a_01_1 = {2f 00 70 00 69 00 6e 00 67 00 3f 00 73 00 74 00 61 00 67 00 65 00 3d 00 31 00 26 00 75 00 69 00 64 00 3d 00 25 00 53 00 26 00 69 00 64 00 3d 00 25 00 64 00 26 00 73 00 75 00 62 00 69 00 64 00 3d 00 25 00 64 00 26 00 6f 00 73 00 3d 00 25 00 64 00 } //1 /ping?stage=1&uid=%S&id=%d&subid=%d&os=%d
		$a_01_2 = {2f 00 70 00 69 00 6e 00 67 00 3f 00 73 00 74 00 61 00 67 00 65 00 3d 00 33 00 26 00 75 00 69 00 64 00 3d 00 25 00 53 00 26 00 65 00 78 00 65 00 63 00 3d 00 25 00 64 00 } //1 /ping?stage=3&uid=%S&exec=%d
		$a_03_3 = {bf 19 00 02 00 57 33 db 53 68 ?? ?? ?? ?? 68 02 00 00 80 ff d6 85 c0 0f ?? ?? ?? ?? ?? 8d ?? ?? 50 57 53 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
rule Rogue_Win32_FakeDef_3{
	meta:
		description = "Rogue:Win32/FakeDef,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 2f 00 61 00 70 00 69 00 2f 00 70 00 69 00 6e 00 67 00 3f 00 73 00 74 00 61 00 67 00 65 00 3d 00 33 00 26 00 75 00 69 00 64 00 3d 00 25 00 53 00 } //1 %s/api/ping?stage=3&uid=%S
		$a_01_1 = {25 00 73 00 2f 00 62 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 2f 00 6b 00 65 00 79 00 2f 00 3f 00 75 00 69 00 64 00 3d 00 25 00 53 00 } //1 %s/billing/key/?uid=%S
		$a_01_2 = {7b 00 72 00 65 00 64 00 7d 00 49 00 4e 00 46 00 45 00 43 00 54 00 45 00 44 00 3a 00 20 00 7b 00 69 00 6e 00 66 00 7d 00 7b 00 7d 00 } //1 {red}INFECTED: {inf}{}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
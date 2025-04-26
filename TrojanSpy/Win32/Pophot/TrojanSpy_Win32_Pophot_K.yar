
rule TrojanSpy_Win32_Pophot_K{
	meta:
		description = "TrojanSpy:Win32/Pophot.K,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 49 75 f9 53 56 57 8b f2 89 45 fc 8b 45 fc e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 f0 e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b d8 d1 fb 79 03 83 d3 00 85 db 7e 48 bf 01 00 00 00 56 8b d7 03 d2 4a b9 02 00 00 00 8b 45 fc e8 } //10
		$a_03_1 = {68 74 74 70 3a 2f 2f [0-0f] 2e 63 6e } //1
		$a_01_2 = {47 45 54 20 2f 2f 79 79 2e 74 78 74 20 48 54 54 50 2f 31 2e 31 } //1 GET //yy.txt HTTP/1.1
		$a_03_3 = {76 65 72 3d [0-05] 26 74 67 69 64 3d [0-0a] 26 61 64 64 72 65 73 73 3d [0-02] 2d } //1
		$a_01_4 = {64 6c 6c 5f 68 69 74 70 6f 70 } //1 dll_hitpop
	condition:
		((#a_02_0  & 1)*10+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}
rule TrojanSpy_Win32_Pophot_K_2{
	meta:
		description = "TrojanSpy:Win32/Pophot.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 00 00 00 ff ff ff ff 0e 00 00 00 43 6f 6d 6d 6f 6e 20 53 74 61 72 74 75 70 00 00 ff ff ff ff 0b 00 00 00 5c 6f 66 66 69 63 65 2e 6c 6e 6b 00 ff ff ff ff } //1
		$a_01_2 = {70 77 69 73 00 00 00 00 ff ff ff ff 06 00 00 00 79 73 2e 69 6e 69 00 00 ff ff ff ff } //1
		$a_01_3 = {6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 00 00 ff ff ff ff 10 00 00 00 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 00 00 00 00 ff ff ff ff 10 00 00 00 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 6d 79 77 65 68 69 74 2e 69 6e 69 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
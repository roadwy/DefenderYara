
rule Trojan_Win32_Vebzenpak_GM_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 00 4b 00 4c 00 57 00 53 00 65 00 6d 00 6a 00 45 00 74 00 38 00 4a 00 6d 00 7a 00 6c 00 4c 00 74 00 59 00 67 00 59 00 64 00 49 00 67 00 73 00 76 00 59 00 72 00 6d 00 54 00 4f 00 38 00 4f 00 30 00 62 00 34 00 31 00 32 00 30 00 } //1 MKLWSemjEt8JmzlLtYgYdIgsvYrmTO8O0b4120
		$a_01_1 = {4b 00 6e 00 6b 00 43 00 67 00 55 00 47 00 57 00 6d 00 49 00 66 00 79 00 55 00 64 00 42 00 66 00 51 00 48 00 46 00 51 00 5a 00 47 00 47 00 39 00 68 00 75 00 76 00 38 00 34 00 33 00 39 00 71 00 52 00 32 00 73 00 58 00 35 00 36 00 65 00 31 00 38 00 35 00 } //1 KnkCgUGWmIfyUdBfQHFQZGG9huv8439qR2sX56e185
		$a_01_2 = {46 00 41 00 66 00 38 00 6d 00 46 00 4a 00 4c 00 73 00 43 00 6d 00 47 00 75 00 71 00 76 00 54 00 65 00 6b 00 49 00 4b 00 73 00 78 00 47 00 66 00 59 00 62 00 6d 00 43 00 55 00 76 00 6b 00 61 00 39 00 6a 00 73 00 31 00 33 00 31 00 } //1 FAf8mFJLsCmGuqvTekIKsxGfYbmCUvka9js131
		$a_01_3 = {6f 00 36 00 58 00 39 00 66 00 36 00 72 00 6f 00 41 00 36 00 48 00 62 00 4f 00 56 00 59 00 6a 00 51 00 54 00 64 00 76 00 4c 00 4d 00 4e 00 62 00 49 00 68 00 41 00 6b 00 31 00 71 00 61 00 4a 00 42 00 7a 00 6e 00 73 00 41 00 6c 00 34 00 78 00 34 00 30 00 } //1 o6X9f6roA6HbOVYjQTdvLMNbIhAk1qaJBznsAl4x40
		$a_01_4 = {75 00 35 00 67 00 31 00 66 00 4e 00 71 00 53 00 5a 00 31 00 49 00 73 00 62 00 55 00 54 00 77 00 6d 00 70 00 79 00 6f 00 72 00 6b 00 76 00 4a 00 64 00 54 00 6d 00 46 00 36 00 72 00 77 00 38 00 39 00 68 00 66 00 6e 00 6d 00 32 00 34 00 53 00 39 00 39 00 } //1 u5g1fNqSZ1IsbUTwmpyorkvJdTmF6rw89hfnm24S99
		$a_01_5 = {70 00 78 00 62 00 4c 00 73 00 6a 00 6b 00 68 00 66 00 33 00 5a 00 51 00 65 00 73 00 58 00 43 00 35 00 41 00 54 00 66 00 6a 00 56 00 34 00 6e 00 61 00 4c 00 72 00 4b 00 4f 00 4d 00 52 00 6c 00 44 00 31 00 30 00 38 00 } //1 pxbLsjkhf3ZQesXC5ATfjV4naLrKOMRlD108
		$a_00_6 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
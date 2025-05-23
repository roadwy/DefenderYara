
rule Trojan_Win32_Tracur_AJ{
	meta:
		description = "Trojan:Win32/Tracur.AJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {33 94 81 00 08 00 00 8b 45 f8 25 ff 00 00 00 8b 4d f4 03 94 81 00 0c 00 00 } //2
		$a_01_1 = {c7 45 f8 2b 9f e3 e6 c7 45 fc f7 ad 83 db 68 00 08 00 00 8d 85 00 f8 ff ff } //2
		$a_01_2 = {6c 6f 61 64 65 72 2e 64 6c 6c 00 73 74 61 72 74 00 75 6e 69 6e 73 74 61 6c 6c 00 } //1
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 00 00 22 2c 73 74 61 72 74 00 } //1
		$a_01_4 = {5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 00 00 00 00 5c 49 6e 62 6f 78 2e 64 62 78 00 } //1
		$a_01_5 = {5c 4d 53 4c 69 63 65 6e 73 69 6e 67 5c 48 61 72 64 77 61 72 65 49 44 00 00 00 43 6c 69 65 6e 74 48 57 49 44 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
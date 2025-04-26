
rule Trojan_Win32_Midie_SIBH_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6a 73 61 6c 66 68 78 68 2e 64 6c 6c } //1 jsalfhxh.dll
		$a_03_1 = {33 c9 85 db 74 ?? 8a 04 39 [0-0a] 34 ?? [0-0a] 04 ?? 34 ?? 88 04 39 41 3b cb 72 ?? 6a 00 57 6a 00 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Midie_SIBH_MTB_2{
	meta:
		description = "Trojan:Win32/Midie.SIBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 63 6e 77 6e 71 73 67 2e 70 64 62 } //1 dcnwnqsg.pdb
		$a_03_1 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-20] 34 ?? [0-20] 34 ?? [0-20] 34 ?? 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Midie_SIBH_MTB_3{
	meta:
		description = "Trojan:Win32/Midie.SIBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 63 6f 6d 70 69 6c 69 6e 67 5c 66 6c 6f 63 6b 5c 61 64 6d 6f 6e 69 73 68 2e 6a 70 67 } //1 \compiling\flock\admonish.jpg
		$a_00_1 = {5c 70 72 6f 76 69 64 65 73 2e 65 78 65 } //1 \provides.exe
		$a_03_2 = {6a 40 57 8d 8d ?? ?? ?? ?? 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 8d 4d ?? 51 57 8d 8d 90 1b 00 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 90 1b 00 81 f9 ?? ?? ?? ?? 74 ?? [0-05] 2c 14 34 84 [0-08] 2c e6 04 5f 34 2f 2c aa [0-08] 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 07 90 18 b0 00 b9 00 00 00 00 8d 85 90 1b 00 ff d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
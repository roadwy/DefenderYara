
rule Trojan_Win32_MustaLoadz_MTB{
	meta:
		description = "Trojan:Win32/MustaLoadz!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {30 fa 4f 1b 4c 91 22 04 ab 48 4e 46 8e 74 33 a3 4e 4a 4c da 7e 62 aa 4d 49 49 85 70 37 ab 4c 47 1b db 70 67 a5 4b 4f 1c 84 73 67 ae 1b 4c 1c dc 47 37 a8 4e 46 4e 80 70 3c 91 4a 4c 1d 81 21 34 93 49 49 4d 81 74 32 91 47 1b 1c 81 24 3d 97 4f 1c 4a 95 24 35 c0 4c 1c 1b c9 } //1
		$a_81_1 = {5c 3f 3f 5c 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 63 68 74 61 73 6b 73 2e 65 78 65 } //1 \??\C:\Windows\system32\schtasks.exe
		$a_00_2 = {83 c4 04 6a 40 68 00 30 00 00 68 20 34 00 00 6a 00 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
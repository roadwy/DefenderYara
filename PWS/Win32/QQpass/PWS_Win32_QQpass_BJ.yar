
rule PWS_Win32_QQpass_BJ{
	meta:
		description = "PWS:Win32/QQpass.BJ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
		$a_00_1 = {31 32 37 2e 30 2e 30 2e 31 [0-10] 6c 6f 63 61 6c 68 6f 73 74 } //1
		$a_00_2 = {61 74 74 72 69 62 20 2d 73 20 2d 68 20 22 } //1 attrib -s -h "
		$a_00_3 = {73 6f 75 6e 64 5c 73 79 73 74 65 6d 2e 77 61 76 } //1 sound\system.wav
		$a_01_4 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //2
		$a_03_5 = {68 04 13 00 00 57 e8 ?? ?? ff ff 48 85 c0 0f 8c e4 00 00 00 40 89 45 ?? 33 f6 c7 45 ?? 01 00 00 00 33 c0 89 45 ?? 33 c0 89 45 ?? c7 45 ?? 00 08 00 00 8b 45 ?? 83 c0 70 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*2+(#a_03_5  & 1)*2) >=7
 
}
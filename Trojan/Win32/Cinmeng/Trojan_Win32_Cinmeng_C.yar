
rule Trojan_Win32_Cinmeng_C{
	meta:
		description = "Trojan:Win32/Cinmeng.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 00 00 7b 33 38 35 41 42 38 43 36 2d 46 42 32 32 2d 34 44 31 37 2d 38 38 33 34 2d 30 36 34 45 32 42 41 30 41 36 46 30 7d } //1
		$a_01_1 = {48 6f 6f 6b 56 65 72 00 48 6f 6f 6b 43 6f 6e 66 69 67 00 00 48 6f 6f 6b 46 6e 61 6d 65 00 00 00 43 6f 6e 66 69 67 2e 63 66 67 } //1
		$a_01_2 = {4d 69 72 63 72 47 46 58 2e 64 61 74 } //1 MircrGFX.dat
		$a_01_3 = {64 33 64 31 63 61 70 73 2e 53 52 47 } //1 d3d1caps.SRG
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_5 = {68 2c 5a d0 00 8d 4d d0 e8 f6 a2 ff ff 3b f3 74 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
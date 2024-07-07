
rule Trojan_Win32_Vidar_PB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 88 8d 0c 06 33 d2 8b c6 f7 75 84 8a 04 3a 8b 55 80 32 04 0a 46 88 01 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Vidar_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {5c 70 6f 6f 6c 2e 65 78 65 } //1 \pool.exe
		$a_00_1 = {5c 70 61 73 74 65 72 2e 65 78 65 } //1 \paster.exe
		$a_00_2 = {5c 75 63 2e 65 78 65 } //1 \uc.exe
		$a_00_3 = {69 70 6c 6f 67 67 65 72 2e 6f 72 67 } //1 iplogger.org
		$a_00_4 = {70 69 78 2d 66 69 78 2e 6e 65 74 } //1 pix-fix.net
		$a_00_5 = {67 61 74 65 31 2e 70 68 70 3f 61 3d 7b 62 62 65 64 33 65 35 35 36 35 36 67 68 66 30 32 2d 30 62 34 31 2d 31 31 65 33 2d 38 32 34 39 7d 69 64 3d 32 } //1 gate1.php?a={bbed3e55656ghf02-0b41-11e3-8249}id=2
		$a_00_6 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 42 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 } //1 cmd.exe /c start /B powershell -windowstyle hidden -command
		$a_02_7 = {27 48 23 6f 72 90 02 0a 73 65 48 6f 90 02 0a 75 72 73 27 27 90 02 0a 29 90 02 0a 7c 90 02 0a 69 90 02 0a 65 90 02 0a 78 27 2e 72 65 70 6c 61 63 65 28 27 90 01 01 27 2c 27 27 29 2e 73 70 6c 69 74 28 27 40 27 2c 35 29 3b 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}
rule Trojan_Win32_Vidar_PB_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.PB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 ea 05 03 54 24 24 8b f8 c1 e7 04 03 7c 24 20 03 c1 33 d7 33 d0 2b f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
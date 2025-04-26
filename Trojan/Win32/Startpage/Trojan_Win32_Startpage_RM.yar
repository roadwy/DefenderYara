
rule Trojan_Win32_Startpage_RM{
	meta:
		description = "Trojan:Win32/Startpage.RM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 0c ?? e8 ?? ?? ?? ?? 6a 64 e8 ?? ?? ?? ?? 6a 00 6a 0d 68 00 01 00 00 } //2
		$a_00_1 = {00 51 2d 24 2d 44 4c 4c 00 } //1
		$a_00_2 = {5c 48 69 64 65 44 65 73 6b 74 6f 70 49 63 6f 6e 73 5c 43 6c 61 73 73 69 63 53 74 61 72 74 4d 65 6e 75 } //1 \HideDesktopIcons\ClassicStartMenu
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 65 6c 65 34 34 34 2e 63 6f 6d 2f 3f } //1 http://www.lele444.com/?
		$a_00_4 = {55 52 4c 3d 68 74 74 70 3a 2f 2f 38 38 38 2e 71 71 32 32 33 33 2e 63 6f 6d 2f } //1 URL=http://888.qq2233.com/
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}

rule Worm_Win32_Ludbaruma_AMTB{
	meta:
		description = "Worm:Win32/Ludbaruma!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 "
		
	strings :
		$a_80_0 = {46 72 6d 62 61 62 6f 6e } //Frmbabon  1
		$a_80_1 = {53 68 65 6c 6c 65 78 65 63 75 74 65 3d 43 65 77 65 6b 5f 49 6d 6f 65 74 2e 65 78 65 } //Shellexecute=Cewek_Imoet.exe  1
		$a_80_2 = {62 61 62 6f 6e 2e 53 43 52 } //babon.SCR  1
		$a_80_3 = {5c 41 6c 6c 20 55 73 65 72 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 45 6d 70 74 79 2e 70 69 66 } //\All Users\Start Menu\Programs\Startup\Empty.pif  1
		$a_80_4 = {4d 69 6b 6f 63 6f 6b 20 57 69 6e 64 6f 6c 6c } //Mikocok Windoll  1
		$a_80_5 = {42 65 75 68 2e 2e 70 69 6e 61 20 6d 75 73 74 69 20 6e 64 61 20 6e 69 20 6c 61 68 2e 20 48 61 68 61 68 61 2e 2e 3a 29 } //Beuh..pina musti nda ni lah. Hahaha..:)  1
		$a_80_6 = {49 74 27 73 20 66 72 65 65 2c 20 75 20 64 6f 6e 27 74 20 6e 65 65 64 20 74 6f 20 70 61 79 2e 2e 3a 50 } //It's free, u don't need to pay..:P  1
		$a_80_7 = {4e 6f 74 65 70 61 64 2e 65 78 65 20 43 3a 5c 77 61 6e 67 73 69 74 2e 74 78 74 } //Notepad.exe C:\wangsit.txt  1
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_10 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100+(#a_80_10  & 1)*-100) >=8
 
}
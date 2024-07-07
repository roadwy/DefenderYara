
rule TrojanClicker_Win32_NightClick_A{
	meta:
		description = "TrojanClicker:Win32/NightClick.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 6f 61 73 5c 55 70 64 5c 52 65 6c 65 61 73 65 5c 77 69 6e 73 74 61 67 65 74 61 73 6b 2e 70 64 62 } //2 \oas\Upd\Release\winstagetask.pdb
		$a_01_1 = {44 00 65 00 73 00 6b 00 57 00 69 00 6e 00 53 00 74 00 61 00 67 00 65 00 } //2 DeskWinStage
		$a_01_2 = {4d 00 79 00 41 00 70 00 70 00 31 00 2e 00 30 00 } //1 MyApp1.0
		$a_01_3 = {25 00 73 00 5c 00 57 00 69 00 6e 00 53 00 74 00 61 00 67 00 65 00 5c 00 25 00 73 00 } //2 %s\WinStage\%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=7
 
}
rule TrojanClicker_Win32_NightClick_A_2{
	meta:
		description = "TrojanClicker:Win32/NightClick.A,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 77 6f 72 6b 5c 6f 61 73 5c } //100 :\work\oas\
		$a_01_1 = {70 00 61 00 72 00 74 00 6e 00 65 00 72 00 69 00 64 00 32 00 3d 00 25 00 64 00 25 00 64 00 } //10 partnerid2=%d%d
		$a_01_2 = {75 00 69 00 64 00 3d 00 75 00 69 00 64 00 } //10 uid=uid
		$a_01_3 = {63 00 6c 00 69 00 63 00 6b 00 20 00 74 00 6f 00 20 00 63 00 6f 00 6f 00 72 00 64 00 20 00 2d 00 20 00 78 00 3a 00 25 00 64 00 20 00 26 00 26 00 20 00 79 00 3a 00 25 00 64 00 } //1 click to coord - x:%d && y:%d
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1) >=111
 
}
rule TrojanClicker_Win32_NightClick_A_3{
	meta:
		description = "TrojanClicker:Win32/NightClick.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 25 00 73 00 26 00 75 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 75 00 62 00 69 00 64 00 3d 00 25 00 73 00 } //1 version=%s&uid=%s&sid=%s&subid=%s
		$a_01_1 = {72 00 61 00 6e 00 67 00 65 00 73 00 6f 00 66 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 rangesoft.org/files/update.exe
		$a_01_2 = {5c 77 6f 72 6b 5c 6f 61 73 5c 75 70 64 53 65 72 76 69 63 65 5c 52 65 6c 65 61 73 65 5c 75 70 64 73 65 72 76 69 63 65 2e 70 64 62 } //1 \work\oas\updService\Release\updservice.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule TrojanClicker_Win32_NightClick_A_4{
	meta:
		description = "TrojanClicker:Win32/NightClick.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 00 25 00 73 00 2f 00 63 00 61 00 6d 00 70 00 61 00 69 00 67 00 6e 00 69 00 64 00 2f 00 32 00 2f 00 75 00 73 00 65 00 72 00 69 00 64 00 2f 00 25 00 73 00 2f 00 73 00 69 00 74 00 65 00 69 00 64 00 2f 00 25 00 73 00 2f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 2f 00 25 00 73 00 } //1 /%s/campaignid/2/userid/%s/siteid/%s/version/%s
		$a_01_1 = {45 3a 5c 77 6f 72 6b 5c 6f 61 73 5c 63 65 66 } //1 E:\work\oas\cef
		$a_01_2 = {7c 00 20 00 70 00 32 00 2e 00 79 00 3a 00 25 00 64 00 7c 00 20 00 70 00 31 00 2e 00 78 00 3a 00 25 00 64 00 20 00 7c 00 20 00 70 00 31 00 2e 00 79 00 3a 00 25 00 64 00 } //1 | p2.y:%d| p1.x:%d | p1.y:%d
		$a_01_3 = {64 00 65 00 62 00 75 00 67 00 5f 00 70 00 61 00 67 00 65 00 5f 00 7a 00 79 00 6b 00 72 00 6f 00 6d 00 3d 00 25 00 64 00 3b 00 } //1 debug_page_zykrom=%d;
		$a_01_4 = {2e 00 70 00 72 00 6f 00 63 00 65 00 65 00 64 00 63 00 68 00 65 00 63 00 6b 00 2e 00 78 00 79 00 7a 00 } //1 .proceedcheck.xyz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanClicker_Win32_NightClick_A_5{
	meta:
		description = "TrojanClicker:Win32/NightClick.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 77 6f 72 6b 5c 6f 61 73 5c } //10 :\work\oas\
		$a_01_1 = {64 00 61 00 74 00 61 00 2e 00 6f 00 61 00 73 00 2d 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 72 00 61 00 6d 00 2f 00 } //1 data.oas-service.com/param/
		$a_01_2 = {64 00 61 00 74 00 61 00 2e 00 72 00 61 00 6e 00 67 00 65 00 73 00 6f 00 66 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 70 00 61 00 72 00 61 00 6d 00 2f 00 } //1 data.rangesoft.org/param/
		$a_01_3 = {64 00 61 00 74 00 61 00 2e 00 73 00 6f 00 6c 00 73 00 63 00 61 00 6e 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 72 00 61 00 6d 00 2f 00 } //1 data.solscanner.com/param/
		$a_01_4 = {73 00 74 00 61 00 74 00 73 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 61 00 64 00 73 00 63 00 61 00 6e 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //1 stats.onlineadscanner.com
		$a_01_5 = {2f 00 25 00 73 00 2f 00 63 00 61 00 6d 00 70 00 61 00 69 00 67 00 6e 00 69 00 64 00 2f 00 32 00 2f 00 75 00 73 00 65 00 72 00 69 00 64 00 2f 00 25 00 73 00 2f 00 73 00 69 00 74 00 65 00 69 00 64 00 2f 00 25 00 73 00 2f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 2f 00 25 00 73 00 } //10 /%s/campaignid/2/userid/%s/siteid/%s/version/%s
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10) >=21
 
}
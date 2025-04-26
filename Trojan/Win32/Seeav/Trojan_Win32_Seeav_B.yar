
rule Trojan_Win32_Seeav_B{
	meta:
		description = "Trojan:Win32/Seeav.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 67 5f 4d 79 43 6f 6d 6d 61 6e 64 5d } //1 [g_MyCommand]
		$a_01_1 = {47 6c 6f 62 61 6c 5c 55 53 42 5f 4e 65 77 5f 49 6e 66 65 63 74 65 64 } //1 Global\USB_New_Infected
		$a_01_2 = {53 59 53 41 46 30 39 31 31 00 } //1 奓䅓うㄹ1
		$a_01_3 = {72 75 73 62 6d 6f 6e 2e 65 78 65 } //1 rusbmon.exe
		$a_01_4 = {4d 44 44 45 46 47 45 47 45 54 47 49 5a 00 } //1 䑍䕄䝆䝅呅䥇Z
		$a_01_5 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 41 54 00 } //1 楍牣獯景屴楗摮睯屳䅄T
		$a_01_6 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 65 73 6b 74 6f 70 2e 69 6e 69 } //1 Microsoft\Windows\Desktop.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
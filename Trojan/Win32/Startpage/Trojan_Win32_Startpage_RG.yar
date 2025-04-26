
rule Trojan_Win32_Startpage_RG{
	meta:
		description = "Trojan:Win32/Startpage.RG,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //1 Start Menu\Programs\Startup
		$a_01_1 = {77 69 6e 64 6f 77 73 5c 73 79 73 2e 63 6d 64 } //1 windows\sys.cmd
		$a_01_2 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e } //1 objShell.Run
		$a_01_3 = {2f 66 20 2f 76 20 22 46 61 76 6f 72 69 74 65 73 22 } //1 /f /v "Favorites"
		$a_01_4 = {30 39 44 7d 5c 73 68 65 6c 6c 5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 } //1 09D}\shell\OpenHomePage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
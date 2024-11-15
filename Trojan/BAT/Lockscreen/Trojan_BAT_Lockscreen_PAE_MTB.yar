
rule Trojan_BAT_Lockscreen_PAE_MTB{
	meta:
		description = "Trojan:BAT/Lockscreen.PAE!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 65 6e 69 74 5f 73 5f 53 63 72 65 65 6e 5f 4c 6f 63 6b 65 72 } //2 Jenit_s_Screen_Locker
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 76 00 34 00 5a 00 4e 00 37 00 6d 00 6d 00 6a 00 } //2 https://pastebin.com/raw/v4ZN7mmj
		$a_01_2 = {69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 2d 00 74 00 79 00 70 00 65 00 20 00 73 00 70 00 79 00 77 00 61 00 72 00 65 00 } //1 infected with Trojan-type spyware
		$a_01_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 } //1 Microsoft\Windows\Start Menu\Programs\Startup
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
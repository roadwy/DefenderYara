
rule Trojan_BAT_Lockscreen_PDR_MTB{
	meta:
		description = "Trojan:BAT/Lockscreen.PDR!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 00 65 00 79 00 67 00 72 00 6f 00 75 00 70 00 37 00 37 00 37 00 } //3 Keygroup777
		$a_01_1 = {4f 00 6d 00 6e 00 69 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 20 00 2d 00 20 00 42 00 41 00 4e 00 47 00 21 00 } //2 Omnilocker - BANG!
		$a_01_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00 } //1 taskkill /im explorer.exe /f
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}
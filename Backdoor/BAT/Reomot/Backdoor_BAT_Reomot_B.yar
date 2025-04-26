
rule Backdoor_BAT_Reomot_B{
	meta:
		description = "Backdoor:BAT/Reomot.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {72 75 6e 73 68 65 6c 6c } //1 runshell
		$a_01_2 = {73 65 6e 64 73 63 72 65 65 6e } //1 sendscreen
		$a_01_3 = {64 6f 6d 65 6c 74 } //1 domelt
		$a_01_4 = {44 65 73 74 72 6f 79 57 65 62 63 61 6d } //1 DestroyWebcam
		$a_01_5 = {73 70 61 6d } //1 spam
		$a_01_6 = {53 74 61 72 74 73 74 72 65 73 73 65 72 } //1 Startstresser
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
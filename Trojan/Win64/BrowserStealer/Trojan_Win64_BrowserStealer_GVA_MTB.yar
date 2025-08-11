
rule Trojan_Win64_BrowserStealer_GVA_MTB{
	meta:
		description = "Trojan:Win64/BrowserStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 d3 ea 41 8b c8 48 d3 e0 40 0f b6 cf 48 8b 7c 24 40 0a d0 41 0f b6 c2 d2 e0 41 0f b6 c9 41 d2 ea 41 0a c2 32 d0 0f b6 c2 } //3
		$a_00_1 = {63 00 68 00 72 00 6f 00 6d 00 65 00 } //1 chrome
		$a_00_2 = {66 00 69 00 72 00 65 00 66 00 6f 00 78 00 } //1 firefox
		$a_00_3 = {6f 00 70 00 65 00 72 00 61 00 } //1 opera
		$a_00_4 = {62 00 72 00 61 00 76 00 65 00 } //1 brave
		$a_00_5 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 20 00 } //3 taskkill /IM 
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*3) >=8
 
}
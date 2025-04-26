
rule TrojanDropper_Win32_Blmoon_A{
	meta:
		description = "TrojanDropper:Win32/Blmoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 14 db 44 24 14 dc 0d ?? ?? ?? 00 da 4c 24 08 } //1
		$a_00_1 = {40 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 49 4d } //1 @taskkill /f /IM
		$a_00_2 = {53 74 61 72 74 75 70 22 20 2b 72 20 2b 61 20 2b 73 20 2b 68 20 2f 73 20 2f 64 } //1 Startup" +r +a +s +h /s /d
		$a_00_3 = {40 65 63 68 6f 20 5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d 20 3e 3e 20 22 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c } //1 @echo [InternetShortcut] >> "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
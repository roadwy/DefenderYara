
rule Trojan_Win32_Pierogi_BM_MSR{
	meta:
		description = "Trojan:Win32/Pierogi.BM!MSR,SIGNATURE_TYPE_PEHSTR,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 55 49 44 2e 62 69 6e } //1 GUID.bin
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 65 73 63 61 6e 6f 72 2e 6c 69 76 65 2f 72 69 70 2f 61 63 65 2f } //1 https://escanor.live/rip/ace/
		$a_01_2 = {4c 6f 61 64 44 6c 6c 46 69 6c 65 73 } //1 LoadDllFiles
		$a_01_3 = {74 65 72 72 65 6c 6c } //1 terrell
		$a_01_4 = {6c 75 63 72 65 74 69 61 } //1 lucretia
		$a_01_5 = {53 65 6e 64 20 53 63 72 65 65 6e 53 68 6f 74 2e 2e 2e 2e } //1 Send ScreenShot....
		$a_01_6 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 57 4d 49 2d 48 4f 53 54 57 49 4e 44 4f 57 53 } //1 \Application Data\WMI-HOSTWINDOWS
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 62 6f 74 2e 68 74 6d 6c } //1 http://www.google.com/bot.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}
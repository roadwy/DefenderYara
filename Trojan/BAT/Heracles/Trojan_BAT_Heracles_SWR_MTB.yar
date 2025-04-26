
rule Trojan_BAT_Heracles_SWR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {64 65 6c 20 2f 46 20 2f 51 20 22 25 64 65 73 74 69 6e 61 74 69 6f 6e 25 22 20 3e 4e 55 4c 20 32 3e 26 31 } //del /F /Q "%destination%" >NUL 2>&1  3
		$a_80_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 22 25 64 65 73 74 69 6e 61 74 69 6f 6e 25 22 20 3e 4e 55 4c 20 32 3e 26 31 } //taskkill /F /IM "%destination%" >NUL 2>&1  2
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce  1
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
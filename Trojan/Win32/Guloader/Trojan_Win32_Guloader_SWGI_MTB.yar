
rule Trojan_Win32_Guloader_SWGI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SWGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {66 6f 72 62 69 64 64 65 6e 6e 65 73 73 5c 55 6e 69 6e 73 74 61 6c 6c 5c 75 72 62 61 6e 69 73 6d 65 6e 5c 65 6b 73 6b 72 65 6d 65 6e 74 61 6c 65 } //2 forbiddenness\Uninstall\urbanismen\ekskrementale
		$a_81_1 = {41 72 6b 74 69 73 6b 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 62 6f 72 74 72 61 74 69 6f 6e 61 6c 69 73 65 72 65 5c 73 74 69 } //1 Arktiske\Uninstall\bortrationalisere\sti
		$a_81_2 = {49 6e 61 70 70 72 65 63 69 61 74 69 76 65 6c 79 5c 75 6e 74 61 63 6b 6c 65 64 } //1 Inappreciatively\untackled
		$a_81_3 = {6f 79 73 74 65 72 62 69 72 64 5c 67 69 70 70 65 64 2e 67 69 66 } //1 oysterbird\gipped.gif
		$a_81_4 = {4c 61 74 69 6e 61 6d 65 72 69 6b 61 73 35 33 2e 65 78 65 } //1 Latinamerikas53.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}
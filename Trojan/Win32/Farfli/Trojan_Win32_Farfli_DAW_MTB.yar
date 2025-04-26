
rule Trojan_Win32_Farfli_DAW_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 83 c0 01 89 45 ec 83 7d ec 04 7d 15 8b 4d f4 03 4d ec 8a 11 80 f2 36 8b 45 f4 03 45 ec 88 10 eb } //3
		$a_01_1 = {63 3a 5c 4d 69 63 72 6f 73 6f 66 74 2e 63 6a 6b } //1 c:\Microsoft.cjk
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 33 36 30 74 72 61 79 2e 65 78 65 20 2f 46 } //1 taskkill /IM 360tray.exe /F
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
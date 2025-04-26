
rule Trojan_Win32_Sluegot_A{
	meta:
		description = "Trojan:Win32/Sluegot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6c 65 74 75 73 67 6f } //1 letusgo
		$a_01_1 = {49 50 48 4f 4e 45 38 2e 35 28 68 6f 73 74 3a 25 73 2c 69 70 3a 25 73 29 } //1 IPHONE8.5(host:%s,ip:%s)
		$a_00_2 = {25 73 5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 66 78 73 73 74 2e 44 4c 4c } //1 %s\Local Settings\fxsst.DLL
		$a_00_3 = {25 73 5c 66 78 73 73 74 2e 64 6c 4c } //1 %s\fxsst.dlL
		$a_00_4 = {3c 79 61 68 6f 6f 20 73 62 3d 22 } //1 <yahoo sb="
		$a_00_5 = {49 6d 65 49 6e 70 75 74 53 65 72 76 69 63 65 73 } //1 ImeInputServices
		$a_01_6 = {6d 6b 63 6d 64 64 6f 77 6e 72 75 6e 20 69 6e 74 65 72 6e 65 74 75 72 6c 20 5b 63 6c 69 65 6e 74 69 64 5d } //1 mkcmddownrun interneturl [clientid]
		$a_01_7 = {61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 53 79 73 54 72 61 79 20 2f 74 20 72 65 67 5f 73 7a 20 2f 66 20 2f 64 } //1 add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SysTray /t reg_sz /f /d
		$a_02_8 = {3d 88 2f 00 00 90 09 10 00 ff 15 ?? ?? ?? ?? 85 c0 75 ?? ff 15 } //1
		$a_01_9 = {8a 11 88 17 8a 10 33 db 88 11 88 18 8d 85 f4 fe ff ff 50 ff 15 a0 40 40 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_02_8  & 1)*1+(#a_01_9  & 1)*2) >=3
 
}
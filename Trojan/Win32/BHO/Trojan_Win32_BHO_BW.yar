
rule Trojan_Win32_BHO_BW{
	meta:
		description = "Trojan:Win32/BHO.BW,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1f 00 06 00 00 "
		
	strings :
		$a_02_0 = {f2 ae 8b cd 4f c1 e9 02 f3 a5 8b cd 5d 83 e1 03 f3 a4 8b fa 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b d1 8b fb 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8d 44 ?? ?? 8d 4c ?? ?? 50 51 6a 00 6a 00 6a 00 6a 00 6a 00 8d 54 ?? ?? 6a 00 52 6a 00 ff 15 } //10
		$a_02_1 = {68 61 6f 63 68 61 6a 69 61 6e 2e 63 6f 6d [0-10] 73 6e 69 66 66 65 72 2e 65 78 65 } //10
		$a_00_2 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //5 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_00_3 = {25 73 2c 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //5 %s,DllUnregisterServer
		$a_00_4 = {73 6c 69 76 65 2e 65 78 65 } //1 slive.exe
		$a_00_5 = {66 6c 69 76 65 2e 64 6c 6c } //1 flive.dll
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=31
 
}
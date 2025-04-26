
rule Trojan_Win32_TurlaCarbonRootkit{
	meta:
		description = "Trojan:Win32/TurlaCarbonRootkit,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 67 00 75 00 73 00 62 00 } //1 \Device\gusb
		$a_01_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 67 00 75 00 73 00 62 00 } //1 \DosDevices\gusb
		$a_01_2 = {5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6d 00 73 00 6e 00 73 00 76 00 63 00 78 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 } //1 \??\C:\Windows\msnsvcx64.dll
		$a_01_3 = {67 75 73 62 2e 73 79 73 } //1 gusb.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
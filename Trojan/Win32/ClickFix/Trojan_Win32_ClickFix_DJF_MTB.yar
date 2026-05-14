
rule Trojan_Win32_ClickFix_DJF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DJF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6f 00 70 00 79 00 20 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 copy C:\WINDOWS\system32\finger.exe
		$a_00_1 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 } //1 \AppData\Local\Temp\
		$a_02_2 = {63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 40 00 [0-96] 7c 00 63 00 6d 00 64 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
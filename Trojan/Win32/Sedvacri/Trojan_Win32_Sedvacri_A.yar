
rule Trojan_Win32_Sedvacri_A{
	meta:
		description = "Trojan:Win32/Sedvacri.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 61 63 6b 65 72 63 69 7c } //1 hackerci|
		$a_01_1 = {73 65 6e 64 76 63 6f 64 65 2f 6d 79 61 70 69 2f } //1 sendvcode/myapi/
		$a_01_2 = {41 50 49 5f 46 69 6e 64 50 61 73 73 77 6f 72 64 } //1 API_FindPassword
		$a_01_3 = {3c 73 70 61 6e 20 73 74 79 6c 65 3d 5c 22 6c 69 6e 65 2d 68 65 69 67 68 74 3a 20 32 38 70 78 3b 5c 22 20 20 20 5c 3e } //1 <span style=\"line-height: 28px;\"   \>
		$a_01_4 = {64 65 6c 20 43 3a 5c 31 32 33 2e 62 61 74 } //1 del C:\123.bat
		$a_01_5 = {5c 64 6d 2e 64 6c 6c 20 2f 73 } //1 \dm.dll /s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
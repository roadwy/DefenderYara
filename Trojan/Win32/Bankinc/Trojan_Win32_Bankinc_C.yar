
rule Trojan_Win32_Bankinc_C{
	meta:
		description = "Trojan:Win32/Bankinc.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {3a 00 38 00 38 00 2f 00 73 00 6f 00 66 00 74 00 2f 00 71 00 71 00 2f 00 72 00 65 00 67 00 2f 00 70 00 6f 00 73 00 74 00 [0-10] 2e 00 61 00 73 00 70 00 3f 00 71 00 71 00 3d 00 00 } //1
		$a_00_1 = {20 00 31 00 32 00 37 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 33 00 20 00 3e 00 6e 00 75 00 6c 00 20 00 32 00 3e 00 6e 00 75 00 6c 00 20 00 3e 00 63 00 3a 00 5c 00 } //1  127.1 -n 3 >nul 2>nul >c:\
		$a_00_2 = {2f 00 73 00 66 00 7a 00 2f 00 67 00 65 00 74 00 71 00 75 00 68 00 61 00 6f 00 2e 00 61 00 73 00 70 00 3f 00 69 00 64 00 3d 00 } //1 /sfz/getquhao.asp?id=
		$a_02_3 = {2f 00 73 00 6f 00 66 00 74 00 2f 00 63 00 68 00 61 00 6e 00 67 00 79 00 6f 00 75 00 2f 00 67 00 65 00 74 00 [0-10] 2e 00 61 00 73 00 70 00 3f 00 69 00 64 00 3d 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}
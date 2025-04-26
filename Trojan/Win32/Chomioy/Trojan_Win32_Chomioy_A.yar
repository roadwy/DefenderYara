
rule Trojan_Win32_Chomioy_A{
	meta:
		description = "Trojan:Win32/Chomioy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 6a 67 e8 ?? ?? ff ff 0f bf c0 50 e8 ?? ?? ff ff 66 85 c0 7d 0e 6a 11 e8 ?? ?? ff ff 66 85 c0 7d 02 b3 01 84 db 74 1f 80 3c 24 00 75 19 c6 04 24 01 6a 40 } //1
		$a_00_1 = {57 00 69 00 6e 00 43 00 45 00 33 00 2e 00 65 00 78 00 65 00 } //1 WinCE3.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
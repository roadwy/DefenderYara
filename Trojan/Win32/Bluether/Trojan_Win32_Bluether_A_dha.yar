
rule Trojan_Win32_Bluether_A_dha{
	meta:
		description = "Trojan:Win32/Bluether.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {88 1e 88 0f 8a 1e 03 d9 81 e3 ff 00 00 00 8a 4c 1c 18 8a 1c 28 32 d9 8b 8c 24 28 01 00 00 88 1c 28 40 3b c1 } //5
		$a_01_1 = {42 00 6c 00 75 00 74 00 68 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //2 Bluthmon.exe
		$a_01_2 = {25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 } //1 %02d-%02d-%02d
		$a_01_3 = {43 3a 5c 54 45 4d 50 5c 32 38 39 30 2e 74 6d 70 } //1 C:\TEMP\2890.tmp
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}
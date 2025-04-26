
rule Trojan_Win32_Swisyn_M_dha{
	meta:
		description = "Trojan:Win32/Swisyn.M!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 08 8a 08 2a ca 32 ca 88 08 40 4e 75 f4 } //1
		$a_03_1 = {81 e5 00 f0 ff ff 81 fd 00 30 00 00 75 ?? 8b 6c 24 18 25 ff 0f 00 00 03 c7 01 28 8b 41 04 } //1
		$a_00_2 = {8d 0c 4a a9 00 00 00 04 8d 14 4e 8b 14 95 d0 40 00 10 } //1
		$a_00_3 = {25 41 50 50 44 41 54 41 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 77 75 61 75 63 6c 74 5c } //1 %APPDATA%\Microsoft\wuauclt\
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
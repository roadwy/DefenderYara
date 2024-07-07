
rule Trojan_Win32_Blorso_B{
	meta:
		description = "Trojan:Win32/Blorso.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 81 f2 90 01 02 e8 90 01 04 8b 55 f4 8b c6 e8 90 01 04 47 66 ff cb 75 d0 90 00 } //1
		$a_00_1 = {53 79 73 74 65 6d 36 34 2e 64 6c 6c } //1 System64.dll
		$a_01_2 = {06 00 00 00 2d 4e 6f 64 33 32 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
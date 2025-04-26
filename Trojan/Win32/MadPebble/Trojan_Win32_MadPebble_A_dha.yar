
rule Trojan_Win32_MadPebble_A_dha{
	meta:
		description = "Trojan:Win32/MadPebble.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 73 75 74 69 6c 2e 65 78 65 20 66 69 6c 65 20 73 65 74 7a 65 72 6f 64 61 74 61 20 6f 66 66 73 65 74 } //1 fsutil.exe file setzerodata offset
		$a_01_1 = {c7 45 e0 50 00 68 00 c7 45 e4 79 00 73 00 c7 45 e8 69 00 63 00 c7 45 ec 61 00 6c 00 c7 45 f0 44 00 72 00 c7 45 f4 69 00 76 00 c7 45 f8 65 00 25 00 c7 45 fc 64 00 00 00 } //1
		$a_01_2 = {c7 45 e0 64 00 6c 00 c7 45 e4 6c 00 3b 00 c7 45 e8 2a 00 2e 00 c7 45 ec 65 00 78 00 c7 45 f0 65 00 3b 00 c7 45 f4 2a 00 2e 00 c7 45 f8 73 00 79 00 c7 45 fc 73 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
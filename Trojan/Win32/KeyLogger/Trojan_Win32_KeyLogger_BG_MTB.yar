
rule Trojan_Win32_KeyLogger_BG_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 33 71 b5 97 6f 33 3f 65 59 e5 4a bd 35 bf c9 a8 1c ad 89 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 5b d1 b8 19 3c 0a ef 4b } //1
		$a_01_1 = {fe 11 7a 90 a5 08 12 4b ab 76 e5 f0 4d b4 80 30 06 a8 d6 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_KeyLogger_BG_MTB_2{
	meta:
		description = "Trojan:Win32/KeyLogger.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {1b 14 6f 38 7a ad ad 00 00 ad 32 67 a2 80 22 6f 58 4b 40 54 54 35 17 17 54 54 17 17 35 35 35 35 35 b0 b0 35 35 17 54 40 3f 2a 2a 58 7f } //2
		$a_01_1 = {4c 00 6f 00 67 00 20 00 53 00 75 00 62 00 6d 00 69 00 74 00 74 00 65 00 64 00 21 00 } //1 Log Submitted!
		$a_01_2 = {63 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6f 00 } //1 c.exe -o
		$a_01_3 = {5b 00 5b 00 50 00 41 00 53 00 54 00 45 00 5d 00 5d 00 } //1 [[PASTE]]
		$a_01_4 = {43 00 20 00 4c 00 20 00 52 00 20 00 20 00 54 00 68 00 65 00 20 00 4c 00 6f 00 67 00 20 00 3f 00 } //1 C L R  The Log ?
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
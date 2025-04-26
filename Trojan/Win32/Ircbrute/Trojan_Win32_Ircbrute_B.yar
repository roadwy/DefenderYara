
rule Trojan_Win32_Ircbrute_B{
	meta:
		description = "Trojan:Win32/Ircbrute.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 56 8d 0c 06 e8 ?? ?? ?? ?? 30 01 83 c4 04 46 3b f7 7c ?? 5f } //1
		$a_00_1 = {83 7d 10 00 8b 4d 08 56 8b f1 74 12 8b 55 0c 8a 02 ff 4d 10 88 01 41 42 83 7d 10 00 75 f1 8b c6 } //1
		$a_01_2 = {25 73 65 72 61 73 65 6d 65 5f 25 64 25 64 25 64 25 64 25 64 2e 65 78 65 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
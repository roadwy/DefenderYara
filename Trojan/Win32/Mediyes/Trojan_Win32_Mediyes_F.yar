
rule Trojan_Win32_Mediyes_F{
	meta:
		description = "Trojan:Win32/Mediyes.F,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c5 8a 54 38 ff 30 14 3b (?? 83 c7|) 01 3b 7e 14 72 ?? 83 7c 24 ?? 10 } //5
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 57 00 69 00 6e 00 53 00 78 00 70 00 } //5 \\.\pipe\WinSxp
		$a_01_2 = {43 2c 01 1a 11 1d 0c 24 24 06 21 3f 03 1b 00 } //1
		$a_01_3 = {44 31 05 1c 05 0a 02 15 11 2d 29 0f 0a 08 09 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}
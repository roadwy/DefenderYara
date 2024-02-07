
rule Trojan_Win32_BadJoke_AM_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeShutdownPrivilege
		$a_01_1 = {44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //01 00  DelNodeRunDLL32
		$a_01_2 = {50 4f 53 54 52 55 4e 50 52 4f 47 52 41 4d } //01 00  POSTRUNPROGRAM
		$a_01_3 = {4c 6f 6c 20 67 65 74 20 65 70 69 63 6c 79 20 72 65 6b 65 64 2f 70 77 6e 65 64 20 62 79 20 6d 79 20 65 70 69 63 20 56 42 53 63 72 69 70 74 21 } //01 00  Lol get epicly reked/pwned by my epic VBScript!
		$a_01_4 = {49 20 63 6f 70 69 65 64 20 46 6c 79 54 65 63 68 27 73 20 68 6f 6d 65 77 6f 72 6b 21 } //01 00  I copied FlyTech's homework!
		$a_01_5 = {47 65 74 20 73 70 61 6d 65 64 } //01 00  Get spamed
		$a_01_6 = {73 74 61 72 74 20 62 6f 78 2e 76 62 73 } //00 00  start box.vbs
	condition:
		any of ($a_*)
 
}
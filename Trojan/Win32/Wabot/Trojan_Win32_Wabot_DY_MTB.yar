
rule Trojan_Win32_Wabot_DY_MTB{
	meta:
		description = "Trojan:Win32/Wabot.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {d0 7e 6b f3 04 dc 48 36 d9 e9 a6 52 c6 1e 04 6d 5b 35 89 73 fd a3 ba fe 41 14 67 03 53 10 41 0f 0d 1a fc } //02 00 
		$a_01_1 = {c8 a4 57 ba 32 c3 69 e8 93 81 e1 87 67 21 e6 4e e4 a1 d4 d7 da c9 ff a5 bd 17 b7 48 47 9a 05 59 63 20 ff 51 3c 53 be } //01 00 
		$a_01_2 = {43 6c 69 63 6b 20 74 6f 20 62 72 65 61 6b 20 69 6e 20 64 65 62 75 67 67 65 72 21 } //00 00  Click to break in debugger!
	condition:
		any of ($a_*)
 
}
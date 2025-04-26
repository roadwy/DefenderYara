
rule Trojan_Win32_VinoSiren_J_dha{
	meta:
		description = "Trojan:Win32/VinoSiren.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 62 63 64 31 66 67 68 69 6a 6b 6c 6d 41 42 43 44 45 46 47 48 2d 4a 2b 4c 4d 6e 6f 70 71 34 73 74 75 76 77 78 79 7a 4e 4f 50 51 37 53 54 55 56 57 58 59 5a 30 65 32 61 72 35 36 52 38 39 4b 2f } //5 3bcd1fghijklmABCDEFGH-J+LMnopq4stuvwxyzNOPQ7STUVWXYZ0e2ar56R89K/
		$a_00_1 = {c1 e9 08 8b 55 f8 c1 ea 02 33 55 f8 8b 45 f8 c1 e8 03 33 d0 8b 45 f8 c1 e8 07 33 d0 c1 e2 18 0b ca } //1
		$a_03_2 = {89 45 fc ba 02 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b d8 33 5d fc ba 03 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 33 d8 ba 07 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 33 d8 c1 e3 18 ba 08 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 0b d8 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=6
 
}
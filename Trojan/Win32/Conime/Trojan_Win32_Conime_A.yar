
rule Trojan_Win32_Conime_A{
	meta:
		description = "Trojan:Win32/Conime.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {c7 45 d4 04 00 02 80 52 c7 45 cc 0a 00 00 00 ff 15 90 01 04 d9 5d 88 d9 45 88 d8 0d 90 01 04 8b 45 dc c7 45 8c 08 00 00 00 89 45 94 df e0 a8 0d 90 00 } //01 00 
		$a_00_1 = {5b 2d 5d 20 45 52 52 4f 52 3a 20 6f 70 2f 20 6c 6f 67 66 } //01 00  [-] ERROR: op/ logf
		$a_00_2 = {63 00 6f 00 6e 00 69 00 6d 00 65 00 } //01 00  conime
		$a_00_3 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 61 00 6c 00 67 00 } //01 00  net stop alg
		$a_00_4 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 73 00 65 00 74 00 20 00 6f 00 70 00 6d 00 6f 00 64 00 65 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 } //01 00  netsh firewall set opmode disable
		$a_00_5 = {3f 00 61 00 63 00 3d 00 67 00 65 00 74 00 26 00 75 00 3d 00 } //00 00  ?ac=get&u=
	condition:
		any of ($a_*)
 
}
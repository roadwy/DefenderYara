
rule Trojan_Win32_Alureon_FR{
	meta:
		description = "Trojan:Win32/Alureon.FR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 8d 7c 00 00 66 39 06 75 06 80 7e 02 24 74 } //02 00 
		$a_01_1 = {eb 36 bb 64 86 00 00 66 3b f3 75 2a 8b b4 d0 88 00 00 00 85 f6 74 1f } //02 00 
		$a_01_2 = {c7 45 f0 48 81 c4 d0 8b 45 f0 89 84 3e 18 02 00 00 c7 45 f4 03 00 00 c3 } //01 00 
		$a_01_3 = {73 75 62 69 64 3d 25 64 26 73 65 3d 25 73 26 6b 65 79 77 6f 72 64 3d 25 73 } //01 00 
		$a_01_4 = {43 6d 64 52 75 6e 45 78 65 55 72 6c 00 43 6d 64 } //00 00 
	condition:
		any of ($a_*)
 
}
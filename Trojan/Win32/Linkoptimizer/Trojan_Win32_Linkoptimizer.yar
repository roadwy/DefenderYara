
rule Trojan_Win32_Linkoptimizer{
	meta:
		description = "Trojan:Win32/Linkoptimizer,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 00 31 2e 64 6c 6c 00 00 00 5c 00 00 00 43 3a 5c 00 63 3a 5c 77 69 6e 64 6f 77 73 00 00 77 69 6e 64 69 72 00 00 53 59 53 54 45 4d 52 4f 4f 54 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 2e 64 6c 6c 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Linkoptimizer_2{
	meta:
		description = "Trojan:Win32/Linkoptimizer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 2e 64 6c 6c 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 00 00 00 00 50 72 6f 67 72 61 6d 46 69 6c 65 73 00 } //01 00 
		$a_01_1 = {6e 75 6c 00 00 4f 70 65 6e 00 00 00 00 2f 63 20 64 65 6c 20 00 43 4f 4d 53 50 45 43 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Linkoptimizer_3{
	meta:
		description = "Trojan:Win32/Linkoptimizer,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 69 64 3d 25 30 38 78 25 30 38 78 25 30 38 78 26 64 69 3d 25 30 38 78 26 70 69 6e 3d 25 30 35 64 26 6c 69 66 65 3d 25 64 26 6c 74 3d 25 64 26 76 30 3d 31 26 6c 3d 25 64 26 64 3d 25 64 26 75 3d 25 64 26 61 63 74 3d 25 64 26 69 63 3d 25 64 } //02 00  uid=%08x%08x%08x&di=%08x&pin=%05d&life=%d&lt=%d&v0=1&l=%d&d=%d&u=%d&act=%d&ic=%d
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 } //02 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\LinkOptimizer
		$a_01_2 = {26 61 63 74 3d 67 63 26 70 69 6e 3d 25 35 64 26 64 3d 25 73 } //02 00  &act=gc&pin=%5d&d=%s
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6c 61 73 68 6b 69 6e 2e 6e 65 74 } //02 00  http://www.flashkin.net
		$a_00_4 = {6c 00 61 00 75 00 74 00 6f 00 63 00 6c 00 69 00 63 00 6b 00 } //02 00  lautoclick
		$a_00_5 = {5f 00 53 00 54 00 45 00 41 00 4c 00 54 00 48 00 5f 00 4c 00 49 00 4e 00 4b 00 5f 00 } //00 00  _STEALTH_LINK_
	condition:
		any of ($a_*)
 
}
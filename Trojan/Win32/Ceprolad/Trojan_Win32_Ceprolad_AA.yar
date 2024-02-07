
rule Trojan_Win32_Ceprolad_AA{
	meta:
		description = "Trojan:Win32/Ceprolad.AA,SIGNATURE_TYPE_CMDHSTR_EXT,16 00 16 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 } //01 00  certutil
		$a_00_1 = {63 00 75 00 72 00 6c 00 } //01 00  curl
		$a_00_2 = {2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 } //01 00  -urlcache
		$a_00_3 = {2d 00 66 00 } //01 00  -f
		$a_00_4 = {2d 00 6f 00 } //0a 00  -o
		$a_00_5 = {68 00 74 00 74 00 70 00 } //0a 00  http
		$a_00_6 = {63 00 69 00 74 00 61 00 74 00 69 00 6f 00 6e 00 73 00 68 00 65 00 72 00 62 00 65 00 2e 00 61 00 74 00 } //00 00  citationsherbe.at
	condition:
		any of ($a_*)
 
}
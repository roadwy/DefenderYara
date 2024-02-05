
rule Trojan_Win32_Swisyn_T{
	meta:
		description = "Trojan:Win32/Swisyn.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 cf 8b fa 03 d2 83 e1 1f 03 d2 c1 ef 1b 33 cf 33 ca 8b d0 } //01 00 
		$a_00_1 = {68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 cf 00 } //01 00 
		$a_02_2 = {68 15 3a 01 00 68 90 90 5d 3a 00 68 c9 75 65 00 e8 90 01 02 00 00 83 c4 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
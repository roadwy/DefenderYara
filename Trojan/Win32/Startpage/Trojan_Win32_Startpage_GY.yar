
rule Trojan_Win32_Startpage_GY{
	meta:
		description = "Trojan:Win32/Startpage.GY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 6f 72 64 3d 25 75 73 26 74 6e 3d 6c 65 69 7a 68 65 6e 26 69 65 } //01 00 
		$a_01_1 = {52 61 69 6e 6d 65 74 65 72 2e 6e 6c 73 00 } //01 00 
		$a_01_2 = {77 69 6e 67 68 6f 00 00 68 61 6f 6b 61 6e 00 00 62 61 69 64 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Alureon_FG{
	meta:
		description = "Trojan:Win32/Alureon.FG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 64 72 5f 66 61 63 65 64 6c 6c } //01 00 
		$a_01_1 = {5b 73 75 62 6a 65 63 74 5f 66 62 5f 65 6e 64 5d } //01 00 
		$a_01_2 = {5b 74 65 78 74 5f 66 62 5f 65 6e 64 5d } //01 00 
		$a_01_3 = {6d 61 69 6e 66 62 2e 73 63 72 69 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Blaruv_A{
	meta:
		description = "Trojan:Win32/Blaruv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 61 70 70 64 61 74 61 25 5c 6e 69 67 68 74 75 70 64 61 74 65 5c } //01 00 
		$a_01_1 = {2f 67 61 74 65 2e 70 68 70 3f 63 6d 64 3d 75 72 6c 73 } //01 00 
		$a_01_2 = {2f 67 61 74 65 2e 70 68 70 3f 72 65 67 3d } //01 00 
		$a_01_3 = {62 6c 61 63 6b 72 65 76 } //00 00 
	condition:
		any of ($a_*)
 
}
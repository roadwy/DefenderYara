
rule Trojan_Win32_Vundo_JI{
	meta:
		description = "Trojan:Win32/Vundo.JI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 74 74 65 6d 70 74 20 74 6f 20 75 73 65 20 4d 53 49 4c 20 63 6f 64 65 } //01 00 
		$a_01_1 = {56 4d 4d 61 69 6e 4d 75 74 65 78 00 56 43 4d 4d 54 58 } //01 00 
		$a_00_2 = {2e 64 6c 6c 00 43 68 65 63 6b 53 61 76 65 00 43 68 65 63 6b 53 74 61 63 6b 00 4f 70 65 6e 53 61 76 65 00 53 68 65 6c 6c 50 61 74 68 00 55 6e 72 65 61 6c } //00 00 
	condition:
		any of ($a_*)
 
}
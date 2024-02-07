
rule Trojan_Win32_Koobface_gen_R{
	meta:
		description = "Trojan:Win32/Koobface.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 7c 56 89 02 e8 } //01 00 
		$a_01_1 = {3f 61 63 74 69 6f 6e 3d 67 6f 6f 67 67 65 6e } //01 00  ?action=googgen
		$a_01_2 = {74 68 65 67 6f 6f 67 2e 74 6d 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}
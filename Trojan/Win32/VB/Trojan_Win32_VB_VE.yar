
rule Trojan_Win32_VB_VE{
	meta:
		description = "Trojan:Win32/VB.VE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6d 72 50 72 6f 74 65 63 74 00 } //01 00 
		$a_01_1 = {74 6d 72 43 65 6e 74 69 6e 65 6c 61 00 } //01 00 
		$a_01_2 = {19 00 00 00 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 00 } //01 00 
		$a_01_3 = {0b 0f 00 04 00 23 78 ff 2a 23 74 ff 76 13 00 2a 23 70 ff 04 6c } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Miuref_H{
	meta:
		description = "Trojan:Win32/Miuref.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {65 72 6e 65 6c 33 32 00 00 00 00 13 } //02 00 
		$a_01_1 = {41 00 6e 00 79 00 2d 00 56 00 69 00 64 00 65 00 6f 00 2d 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}
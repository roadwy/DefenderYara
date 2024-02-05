
rule Trojan_Win32_Emotet_EM{
	meta:
		description = "Trojan:Win32/Emotet.EM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 72 63 68 69 74 65 63 74 75 72 65 6f 74 68 65 41 6e 6e 6f 75 6e 63 65 6d 65 6e 74 } //01 00 
		$a_01_1 = {6d 6f 75 73 65 2d 63 6c 69 63 6b 69 6e 67 57 75 73 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}
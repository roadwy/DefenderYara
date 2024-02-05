
rule Trojan_Win32_Eqtonex_C{
	meta:
		description = "Trojan:Win32/Eqtonex.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 61 69 6e 57 72 61 70 70 65 72 90 02 20 5f 73 65 74 56 61 6c 69 64 61 74 65 90 02 20 5f 73 65 74 50 72 6f 63 65 73 73 90 02 20 5f 73 65 74 49 44 90 02 20 5f 64 65 6c 65 74 65 90 02 20 5f 63 72 65 61 74 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
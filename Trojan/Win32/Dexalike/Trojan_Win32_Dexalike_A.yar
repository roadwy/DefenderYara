
rule Trojan_Win32_Dexalike_A{
	meta:
		description = "Trojan:Win32/Dexalike.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 72 00 65 00 74 00 75 00 72 00 6e 00 3d 00 90 02 30 68 00 74 00 74 00 70 00 90 00 } //01 00 
		$a_02_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 68 00 74 00 74 00 70 00 90 02 f0 72 00 65 00 74 00 75 00 72 00 6e 00 3d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
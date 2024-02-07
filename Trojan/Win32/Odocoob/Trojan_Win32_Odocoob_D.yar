
rule Trojan_Win32_Odocoob_D{
	meta:
		description = "Trojan:Win32/Odocoob.D,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6f 00 64 00 62 00 63 00 63 00 6f 00 6e 00 66 00 } //01 00  odbcconf
		$a_02_1 = {7b 00 72 00 65 00 67 00 73 00 76 00 72 00 20 00 90 02 06 5c 00 5c 00 90 00 } //01 00 
		$a_02_2 = {7b 00 72 00 65 00 67 00 73 00 76 00 72 00 20 00 90 02 06 68 00 74 00 74 00 70 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
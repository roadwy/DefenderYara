
rule Trojan_Win32_DataCompress_B_7zip{
	meta:
		description = "Trojan:Win32/DataCompress.B!7zip,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {37 00 7a 00 61 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_1 = {20 00 37 00 7a 00 61 00 20 00 } //f6 ff 
		$a_00_2 = {2d 00 2d 00 68 00 65 00 6c 00 70 00 } //01 00 
	condition:
		any of ($a_*)
 
}
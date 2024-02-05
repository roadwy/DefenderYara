
rule Trojan_Win32_DataCompress_VC{
	meta:
		description = "Trojan:Win32/DataCompress.VC,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 90 02 10 2d 00 72 00 90 00 } //01 00 
		$a_02_1 = {7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 90 02 10 2d 00 63 00 6f 00 6e 00 66 00 69 00 67 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
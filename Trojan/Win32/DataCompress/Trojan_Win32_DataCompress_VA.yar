
rule Trojan_Win32_DataCompress_VA{
	meta:
		description = "Trojan:Win32/DataCompress.VA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {37 00 7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
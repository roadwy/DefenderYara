
rule Trojan_Win32_DataCompress_B_rar{
	meta:
		description = "Trojan:Win32/DataCompress.B!rar,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {72 00 61 00 72 00 20 00 } //1 rar 
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
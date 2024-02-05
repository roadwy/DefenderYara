
rule Trojan_Win32_BITSAbusePer_AJ_ps{
	meta:
		description = "Trojan:Win32/BITSAbusePer.AJ!ps,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_02_0 = {73 00 74 00 61 00 72 00 74 00 2d 00 62 00 69 00 74 00 73 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 90 02 0a 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 90 02 80 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
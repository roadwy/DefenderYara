
rule Trojan_Win32_MpTamperDisableFeatureWd_A{
	meta:
		description = "Trojan:Win32/MpTamperDisableFeatureWd.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6f 00 6e 00 6c 00 69 00 6e 00 65 00 90 02 10 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 2d 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 90 02 10 66 00 65 00 61 00 74 00 75 00 72 00 65 00 6e 00 61 00 6d 00 65 00 3a 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
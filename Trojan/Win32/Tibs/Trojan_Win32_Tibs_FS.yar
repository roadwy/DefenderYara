
rule Trojan_Win32_Tibs_FS{
	meta:
		description = "Trojan:Win32/Tibs.FS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {87 d1 58 68 90 01 04 ff 15 90 01 04 68 00 00 00 01 6a 00 f7 64 24 04 83 c4 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
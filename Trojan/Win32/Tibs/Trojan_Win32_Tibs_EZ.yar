
rule Trojan_Win32_Tibs_EZ{
	meta:
		description = "Trojan:Win32/Tibs.EZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 ce 31 c9 81 c1 90 01 04 81 e9 90 01 04 8d 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
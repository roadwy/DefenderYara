
rule Trojan_Win32_Tibs_FN{
	meta:
		description = "Trojan:Win32/Tibs.FN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {87 d1 81 c4 90 01 04 81 ec 90 01 04 68 90 01 04 ff 15 90 01 09 f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
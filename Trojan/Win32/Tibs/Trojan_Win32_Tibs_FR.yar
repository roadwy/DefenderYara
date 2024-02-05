
rule Trojan_Win32_Tibs_FR{
	meta:
		description = "Trojan:Win32/Tibs.FR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 10 90 02 02 69 90 01 01 00 00 01 00 90 09 09 00 90 02 04 b8 90 03 03 04 90 01 10 90 09 12 00 90 02 40 ad 35 90 01 04 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
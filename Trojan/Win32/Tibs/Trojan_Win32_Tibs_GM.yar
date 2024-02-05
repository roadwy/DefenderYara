
rule Trojan_Win32_Tibs_GM{
	meta:
		description = "Trojan:Win32/Tibs.GM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d6 52 66 ad c1 e0 90 01 01 66 ad c1 c8 90 01 01 c1 c0 90 01 01 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
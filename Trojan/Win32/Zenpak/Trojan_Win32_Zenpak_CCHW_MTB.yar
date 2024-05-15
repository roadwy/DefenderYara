
rule Trojan_Win32_Zenpak_CCHW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c3 40 89 d0 48 31 1d 90 01 04 89 c2 42 83 ea 02 89 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
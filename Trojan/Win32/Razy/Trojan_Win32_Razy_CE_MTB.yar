
rule Trojan_Win32_Razy_CE_MTB{
	meta:
		description = "Trojan:Win32/Razy.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {74 01 ea 31 1e 89 c8 89 ca 81 c6 04 00 00 00 81 ea 90 02 04 39 fe 75 e5 90 00 } //02 00 
		$a_01_1 = {74 01 ea 31 30 41 81 c0 04 00 00 00 47 39 d0 75 ed } //00 00 
	condition:
		any of ($a_*)
 
}
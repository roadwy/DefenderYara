
rule Trojan_Win32_Zenpak_ASQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 02 6b c2 90 01 01 8b 4c 24 90 02 04 29 c1 89 c8 83 e8 02 89 4c 24 90 01 01 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
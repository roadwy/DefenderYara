
rule Trojan_Win32_Zenpak_ASN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 6b c2 11 8b 4e 90 01 01 29 c1 89 c8 83 e8 07 89 4e 90 01 01 89 46 90 01 01 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
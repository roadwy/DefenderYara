
rule Trojan_Win32_Zenpak_MD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 45 fc b9 6d 78 29 cc 89 45 d8 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d d8 29 c1 89 c8 83 e8 08 89 4d d4 89 45 d0 74 } //00 00 
	condition:
		any of ($a_*)
 
}
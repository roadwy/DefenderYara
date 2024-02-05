
rule Trojan_Win32_Zenpak_AQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {b9 6d 78 29 cc 89 44 24 64 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 64 29 c1 89 c8 83 e8 0d 89 4c 24 60 89 44 24 5c 0f } //00 00 
	condition:
		any of ($a_*)
 
}
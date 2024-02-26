
rule Trojan_Win32_Zenpak_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 6b c2 90 01 01 8b 4d 90 01 01 29 c1 89 c8 83 e8 08 89 4d 90 01 01 89 45 90 01 01 74 90 00 } //01 00 
		$a_03_1 = {f7 e1 c1 ea 02 6b c2 90 01 01 8b 4d ec 29 c1 89 c8 83 e8 90 01 01 89 4d 90 01 01 89 45 90 01 01 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Zenpak_ASW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 03 6b c2 90 01 01 8b 8c 90 01 03 00 00 29 c1 89 c8 83 e8 90 01 01 89 90 01 01 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
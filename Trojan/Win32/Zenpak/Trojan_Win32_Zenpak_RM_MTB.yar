
rule Trojan_Win32_Zenpak_RM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 0f b6 c1 8b 4d 90 01 01 8a 84 05 90 01 04 30 04 0a 42 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
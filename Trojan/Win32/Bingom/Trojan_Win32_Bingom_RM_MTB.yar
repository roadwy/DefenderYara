
rule Trojan_Win32_Bingom_RM_MTB{
	meta:
		description = "Trojan:Win32/Bingom.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 ef 50 00 00 66 31 85 90 01 04 6a 06 a5 59 66 8b 54 4d 90 01 01 8d 44 4d 90 01 01 66 31 10 49 3b cb 7f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
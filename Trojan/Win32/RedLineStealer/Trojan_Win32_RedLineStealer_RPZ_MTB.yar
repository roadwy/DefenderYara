
rule Trojan_Win32_RedLineStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 db b8 11 00 00 00 83 c0 1f 64 8b 3c 03 8b 7f 0c 8b 77 14 8b 36 8b 36 8b 46 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 02 f6 bf 50 eb 02 8d 43 e8 1a 00 00 00 eb 04 be da 68 17 eb } //00 00 
	condition:
		any of ($a_*)
 
}
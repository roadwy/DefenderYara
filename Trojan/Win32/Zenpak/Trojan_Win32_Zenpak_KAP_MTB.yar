
rule Trojan_Win32_Zenpak_KAP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 2c 32 8b 15 90 01 04 30 cd 88 2d 90 01 04 c7 05 90 01 08 81 c2 90 01 04 89 15 90 01 04 8b 55 90 01 01 88 2c 32 8b 55 90 01 01 39 d7 89 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
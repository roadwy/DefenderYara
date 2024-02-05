
rule Trojan_Win32_Khalesi_RW_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 04 00 00 00 c1 e0 00 8b 4d 90 01 01 8b 14 01 89 55 90 01 01 c7 45 90 01 01 b9 79 37 9e 8b 45 90 01 01 c1 e0 05 89 45 90 01 01 c7 45 90 01 01 00 00 00 00 eb 90 01 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 83 7d 90 01 01 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
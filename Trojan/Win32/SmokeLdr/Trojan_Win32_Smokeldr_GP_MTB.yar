
rule Trojan_Win32_Smokeldr_GP_MTB{
	meta:
		description = "Trojan:Win32/Smokeldr.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 51 8d 55 90 01 01 52 e8 90 01 04 8b 45 90 01 01 50 8d 4d 90 01 01 51 e8 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
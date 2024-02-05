
rule Trojan_Win32_Zusy_AZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 a8 f2 04 10 53 89 44 24 44 ff d6 68 b8 f2 04 10 53 89 44 24 48 ff d6 68 c8 f2 04 10 53 89 44 24 4c ff d6 8b 5c 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}
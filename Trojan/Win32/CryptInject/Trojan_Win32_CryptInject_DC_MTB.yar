
rule Trojan_Win32_CryptInject_DC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 8a 11 02 55 f8 8b 45 08 88 10 8b 4d 08 8a 11 32 55 f8 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb 9e } //00 00 
	condition:
		any of ($a_*)
 
}
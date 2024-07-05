
rule Trojan_Win32_CryptInject_DDI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 0f b6 82 90 01 04 8b 4d fc 81 e1 03 00 00 80 79 05 49 83 c9 fc 41 0f b6 91 90 01 04 33 c2 8b 4d fc 88 81 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
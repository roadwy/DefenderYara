
rule Trojan_Win32_CryptInject_SN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 68 90 01 02 00 00 6a 00 e8 90 01 04 89 45 fc 33 c9 bb 90 00 } //02 00 
		$a_02_1 = {85 c9 76 33 8b c1 bf 05 00 00 00 33 d2 f7 f7 85 d2 75 90 01 01 8a 03 34 90 01 01 8b 55 fc 03 d1 73 05 e8 90 01 04 88 02 eb 10 8b 45 fc 03 c1 73 05 e8 90 01 04 8a 13 88 10 41 43 81 f9 90 01 02 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
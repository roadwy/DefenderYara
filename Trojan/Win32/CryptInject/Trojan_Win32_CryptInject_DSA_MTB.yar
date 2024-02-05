
rule Trojan_Win32_CryptInject_DSA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c0 8b c0 eb 90 01 01 33 05 90 01 04 8b c0 8b c0 90 00 } //01 00 
		$a_02_1 = {8b c0 8b c8 8b d1 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5f 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
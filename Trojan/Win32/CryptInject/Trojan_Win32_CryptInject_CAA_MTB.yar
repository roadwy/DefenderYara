
rule Trojan_Win32_CryptInject_CAA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 eb 01 81 c3 90 01 04 81 f3 90 01 04 81 e3 90 01 04 c1 eb 04 81 f3 90 01 04 89 d9 5b 89 4c 24 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_CryptInject_BKC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b 44 24 08 5d 01 c5 32 5d 00 81 e3 ff 00 00 00 8b 14 24 8b 2a c1 e3 02 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_CryptInject_EC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e0 01 85 c0 74 90 01 01 8a 45 90 01 01 30 45 90 01 01 8a 45 90 01 01 83 e0 90 01 01 88 45 90 01 01 d0 65 90 01 01 80 7d 90 01 02 74 90 01 01 80 75 90 01 02 d0 6d 90 01 01 ff 45 90 01 01 83 7d 90 01 02 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
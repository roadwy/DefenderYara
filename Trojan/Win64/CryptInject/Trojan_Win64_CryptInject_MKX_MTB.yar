
rule Trojan_Win64_CryptInject_MKX_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 ff c0 48 89 04 24 48 8b 44 24 30 48 39 04 24 73 28 48 8b 04 24 48 8b 4c 24 28 48 03 c8 48 8b c1 0f be 00 83 f0 2e 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 eb } //00 00 
	condition:
		any of ($a_*)
 
}
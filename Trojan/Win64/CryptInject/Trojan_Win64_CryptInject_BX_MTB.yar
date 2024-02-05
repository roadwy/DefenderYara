
rule Trojan_Win64_CryptInject_BX_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 38 8b 40 28 48 8b 4c 24 28 48 03 c8 48 8b c1 48 89 44 24 78 ff 54 24 78 } //00 00 
	condition:
		any of ($a_*)
 
}
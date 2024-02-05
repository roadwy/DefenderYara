
rule Trojan_Win64_CryptInject_LKA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 0f b7 35 96 a7 35 00 66 89 71 04 66 c7 41 06 01 00 8b cb c1 e9 1f 03 cb c1 f9 01 48 63 c9 66 c7 04 48 00 00 48 83 c4 28 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win64_CryptInject_ID_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 01 ff 83 90 01 04 8b 83 90 01 04 2b 43 54 48 63 8b 90 01 04 2d 3f 6b 0d 00 09 83 90 01 04 48 8b 83 90 01 04 44 88 04 01 8b 83 90 01 04 ff 83 90 01 04 33 43 24 35 38 f7 06 00 89 83 90 01 04 49 81 f9 90 00 } //01 00 
		$a_01_1 = {73 6c 6c 37 30 37 78 69 33 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
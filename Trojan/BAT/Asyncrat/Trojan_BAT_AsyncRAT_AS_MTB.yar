
rule Trojan_BAT_AsyncRAT_AS_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 fd a2 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 62 00 00 00 1f 00 00 00 39 00 00 00 dd } //01 00 
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_01_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  MD5CryptoServiceProvider
	condition:
		any of ($a_*)
 
}
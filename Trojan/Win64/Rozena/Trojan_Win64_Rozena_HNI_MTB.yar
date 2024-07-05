
rule Trojan_Win64_Rozena_HNI_MTB{
	meta:
		description = "Trojan:Win64/Rozena.HNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 09 54 88 c9 ff d5 48 } //00 00 
	condition:
		any of ($a_*)
 
}
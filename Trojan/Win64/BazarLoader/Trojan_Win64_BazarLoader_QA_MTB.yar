
rule Trojan_Win64_BazarLoader_QA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 8b 49 f8 49 ff ca 41 8b 11 49 03 ce 45 8b 41 fc 48 03 d6 4d 85 c0 74 19 0f 1f 80 00 00 00 00 0f b6 02 48 ff c2 88 01 48 8d 49 01 49 83 e8 01 75 ee 49 83 c1 28 4d 85 d2 75 c5 } //00 00 
	condition:
		any of ($a_*)
 
}
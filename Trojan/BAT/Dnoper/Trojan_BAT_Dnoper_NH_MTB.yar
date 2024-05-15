
rule Trojan_BAT_Dnoper_NH_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 90 01 01 08 00 04 0e 06 17 59 95 58 0e 05 28 d1 0d 00 06 58 54 2a 90 00 } //02 00 
		$a_81_1 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  System.Security.Cryptography.AesCryptoServiceProvider
	condition:
		any of ($a_*)
 
}
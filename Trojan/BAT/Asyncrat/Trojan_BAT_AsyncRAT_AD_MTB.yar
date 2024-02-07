
rule Trojan_BAT_AsyncRAT_AD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 06 17 58 13 06 11 06 1e 32 de 09 69 8d 90 01 01 00 00 01 25 17 73 90 01 01 00 00 0a 13 04 06 6f 90 01 01 00 00 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f 90 00 } //02 00 
		$a_01_1 = {4b 6f 69 56 4d 2e 52 75 6e 74 69 6d 65 } //00 00  KoiVM.Runtime
	condition:
		any of ($a_*)
 
}
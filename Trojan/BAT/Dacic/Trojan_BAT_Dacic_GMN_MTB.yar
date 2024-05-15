
rule Trojan_BAT_Dacic_GMN_MTB{
	meta:
		description = "Trojan:BAT/Dacic.GMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {69 11 0d 20 90 01 04 61 58 8d 90 01 04 13 0c 20 90 01 03 e8 11 0d 5a 39 90 01 04 11 08 11 0d 20 90 01 04 64 13 0d 11 0c 11 0d 20 90 01 03 e8 59 13 0d 11 0d 20 90 01 03 1b 61 6f 90 01 03 0a 11 0c 11 08 8e 11 0d 20 90 01 04 59 13 0d 69 11 0d 20 90 01 03 7c 61 13 0d d0 90 01 04 20 90 01 03 f5 11 0d 61 13 0d 28 ab 00 00 0a 11 0d 20 0d 82 87 fb 61 13 0d a2 20 90 01 03 b6 11 0d 20 1f 00 00 00 5f 62 90 00 } //01 00 
		$a_80_1 = {50 4c 6f 61 64 65 72 2e 65 78 65 } //PLoader.exe  00 00 
	condition:
		any of ($a_*)
 
}
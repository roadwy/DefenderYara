
rule Trojan_BAT_DllInject_MBFF_MTB{
	meta:
		description = "Trojan:BAT/DllInject.MBFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d 16 13 06 38 00 00 00 00 03 16 e0 28 90 01 01 00 00 0a 16 09 08 16 12 00 28 90 01 01 00 00 06 13 04 16 13 07 38 00 00 00 00 11 04 20 10 27 00 00 90 00 } //01 00 
		$a_01_1 = {63 32 35 33 35 32 31 66 33 64 30 33 } //00 00 
	condition:
		any of ($a_*)
 
}
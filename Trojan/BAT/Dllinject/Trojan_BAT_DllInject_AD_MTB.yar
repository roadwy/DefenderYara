
rule Trojan_BAT_DllInject_AD_MTB{
	meta:
		description = "Trojan:BAT/DllInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 12 07 08 9a 25 6f 09 00 00 0a 6f 0a 00 00 0a 08 17 58 0c 08 07 8e 69 32 e8 } //01 00 
		$a_01_1 = {55 70 64 61 74 65 72 } //00 00  Updater
	condition:
		any of ($a_*)
 
}
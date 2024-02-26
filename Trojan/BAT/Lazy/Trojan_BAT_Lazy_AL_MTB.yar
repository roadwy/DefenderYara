
rule Trojan_BAT_Lazy_AL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {fe 0c 02 00 20 01 00 00 00 fe 01 39 12 00 00 00 73 90 01 03 0a fe 0e 00 00 20 02 00 00 00 fe 0e 02 00 00 fe 0c 02 00 20 03 00 00 00 fe 01 39 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lazy_AL_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 05 08 07 11 05 17 6f 96 00 00 0a 6f 97 00 00 0a 26 11 04 17 d6 13 04 11 04 09 31 d2 } //01 00 
		$a_01_1 = {47 00 72 00 61 00 64 00 69 00 65 00 6e 00 74 00 20 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  Gradient Crypter.exe
	condition:
		any of ($a_*)
 
}
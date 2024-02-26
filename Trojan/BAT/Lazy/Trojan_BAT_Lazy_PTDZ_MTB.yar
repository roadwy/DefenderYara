
rule Trojan_BAT_Lazy_PTDZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {04 20 ff 00 00 00 5f 2b 1d 03 6f 31 00 00 0a 0c 2b 17 08 06 08 06 93 02 7b 0b 00 00 04 07 91 } //00 00 
	condition:
		any of ($a_*)
 
}
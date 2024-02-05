
rule Trojan_BAT_Lazy_PSJV_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 08 00 00 06 13 02 38 12 00 00 00 fe 0c 00 00 45 01 00 00 00 3c 00 00 00 38 37 00 00 00 28 02 00 00 0a 11 02 28 0c 00 00 06 28 0d 00 00 06 28 0e 00 00 06 13 03 20 00 00 00 00 7e 5e 00 00 04 7b 6c 00 00 04 39 c6 ff ff ff 26 20 00 00 00 00 38 bb ff ff ff dd 10 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
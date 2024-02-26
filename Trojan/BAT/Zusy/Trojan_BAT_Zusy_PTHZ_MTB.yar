
rule Trojan_BAT_Zusy_PTHZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {38 08 f5 ff ff 28 90 01 01 00 00 0a fe 0c 01 00 6f 29 00 00 0a 28 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
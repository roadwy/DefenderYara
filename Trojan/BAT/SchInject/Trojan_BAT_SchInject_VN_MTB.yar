
rule Trojan_BAT_SchInject_VN_MTB{
	meta:
		description = "Trojan:BAT/SchInject.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 72 90 01 03 70 18 18 8d 90 01 03 01 25 17 18 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 72 90 01 03 70 a2 a2 28 90 01 03 0a 26 72 90 01 03 70 13 90 01 01 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
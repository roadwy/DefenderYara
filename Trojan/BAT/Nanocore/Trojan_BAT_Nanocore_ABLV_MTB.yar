
rule Trojan_BAT_Nanocore_ABLV_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 03 8e 69 0c 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 90 01 03 0a 03 04 17 58 08 5d 91 28 90 01 03 0a 59 06 58 06 5d d2 0d 09 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
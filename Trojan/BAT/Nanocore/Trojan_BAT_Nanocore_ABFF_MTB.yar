
rule Trojan_BAT_Nanocore_ABFF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 11 07 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 07 17 58 13 07 11 07 20 90 01 03 00 fe 04 13 08 11 08 2d d9 28 90 01 03 0a 07 6f 90 01 03 0a 6f 90 01 03 0a 0c 08 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}

rule Trojan_BAT_Nanocore_AAER_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AAER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0a 06 7e 90 01 01 00 00 04 16 6f 90 01 01 00 00 0a 20 39 05 00 00 59 7d 90 01 01 00 00 04 7e 90 01 01 00 00 04 17 6f 90 01 01 00 00 0a 06 fe 90 01 02 03 00 06 73 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 73 90 01 01 00 00 0a 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
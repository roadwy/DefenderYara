
rule Trojan_BAT_RedLine_MBEH_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 40 1f 00 00 28 90 01 01 00 00 0a 20 f0 0f 00 00 28 90 01 01 00 00 0a 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 0a 0a 73 90 01 01 00 00 0a 7e 90 01 01 00 00 04 06 6f 90 01 01 00 00 0a 20 77 32 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
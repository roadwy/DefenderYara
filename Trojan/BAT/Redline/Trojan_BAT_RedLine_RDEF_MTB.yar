
rule Trojan_BAT_RedLine_RDEF_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 6f 7b 01 00 0a 02 14 7d fd 00 00 04 6f 7c 01 00 0a 7e fa 00 00 04 25 } //00 00 
	condition:
		any of ($a_*)
 
}
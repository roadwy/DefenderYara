
rule Trojan_BAT_OrcusRAT_RE_MTB{
	meta:
		description = "Trojan:BAT/OrcusRAT.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 18 5b 8d 22 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 08 18 58 0c 08 06 32 e4 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
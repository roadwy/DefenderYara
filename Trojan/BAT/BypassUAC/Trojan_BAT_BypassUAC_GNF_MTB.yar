
rule Trojan_BAT_BypassUAC_GNF_MTB{
	meta:
		description = "Trojan:BAT/BypassUAC.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 0a 02 28 90 01 03 06 0b 07 8e 69 8d 1d 00 00 01 0c 16 0d 2b 13 08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 07 8e 69 32 e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
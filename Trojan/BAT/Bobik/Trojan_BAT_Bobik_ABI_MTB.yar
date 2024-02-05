
rule Trojan_BAT_Bobik_ABI_MTB{
	meta:
		description = "Trojan:BAT/Bobik.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a2 09 18 72 43 01 00 70 a2 09 19 28 90 01 03 0a a2 09 1a 72 6f 01 00 70 a2 09 1b 08 16 9a 6f 90 01 03 0a a2 09 1c 72 7f 01 00 70 a2 09 1d 28 90 01 03 0a a2 09 1e 72 9b 01 00 70 a2 09 1f 09 28 90 01 03 0a a2 09 1f 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
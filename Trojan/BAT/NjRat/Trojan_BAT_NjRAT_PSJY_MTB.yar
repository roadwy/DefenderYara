
rule Trojan_BAT_NjRAT_PSJY_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 1f 1a 28 90 01 03 0a 72 bd 01 00 70 20 90 01 03 00 28 90 01 03 06 08 28 90 01 03 0a 13 04 73 90 01 03 0a 28 90 01 03 0a 09 6f 90 01 03 0a 28 90 01 03 0a 13 05 2b 03 0c 2b a5 11 04 11 05 28 90 01 03 0a 2b 06 0b 38 78 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_NanoBot_DH_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 20 64 06 83 67 02 5a 0a 06 1f 0b 63 0b 02 06 1f 1f 5f 63 0c 28 90 01 04 00 07 08 58 0d 09 13 04 2b 00 11 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
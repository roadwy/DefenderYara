
rule Trojan_Win64_LokiBot_RDH_MTB{
	meta:
		description = "Trojan:Win64/LokiBot.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 c9 48 8d 40 01 33 ca 69 d1 fb e3 ed 25 0f b6 08 84 c9 } //00 00 
	condition:
		any of ($a_*)
 
}
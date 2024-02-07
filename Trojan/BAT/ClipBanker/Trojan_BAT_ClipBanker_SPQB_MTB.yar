
rule Trojan_BAT_ClipBanker_SPQB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SPQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 07 00 "
		
	strings :
		$a_01_0 = {7e 0e 00 00 04 08 7e 0d 00 00 04 08 91 7e 0c 00 00 04 08 7e 0c 00 00 04 8e 69 5d 91 06 58 20 ff 00 00 00 5f 61 d2 9c 08 17 58 0c 08 7e 0e 00 00 04 8e 69 17 59 fe 02 16 fe 01 0d 09 2d c2 } //01 00 
		$a_01_1 = {4c 6f 6e 61 2e 70 64 62 } //00 00  Lona.pdb
	condition:
		any of ($a_*)
 
}
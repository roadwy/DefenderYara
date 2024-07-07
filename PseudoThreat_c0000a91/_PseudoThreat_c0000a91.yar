
rule _PseudoThreat_c0000a91{
	meta:
		description = "!PseudoThreat_c0000a91,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 90 01 01 53 90 03 06 04 33 c9 56 57 89 4d 56 57 c7 45 90 02 20 99 f7 7d 0c 8b 90 01 02 90 03 01 01 89 8b 90 01 02 90 03 01 01 89 8b 90 02 0a 88 45 ff 60 33 c0 8a 45 ff 33 c9 8b 4d f4 d2 c8 88 45 ff 61 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
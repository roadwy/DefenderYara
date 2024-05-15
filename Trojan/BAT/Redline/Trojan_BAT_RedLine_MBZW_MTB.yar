
rule Trojan_BAT_RedLine_MBZW_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e 00 45 75 67 65 6e 65 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 62 6c 56 76 37 77 4c 55 73 73 54 31 37 } //00 00  䴼摯汵㹥䔀杵湥e卍彇䕎T扏敪瑣戀噬㝶䱷獕味㜱
	condition:
		any of ($a_*)
 
}
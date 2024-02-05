
rule Trojan_BAT_Jigsaw_PSNE_MTB{
	meta:
		description = "Trojan:BAT/Jigsaw.PSNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {26 38 c2 f8 ff ff 11 16 17 58 13 16 11 1a 20 38 3b 25 12 5a 20 8a 58 b4 76 61 38 a9 f8 ff ff 1f 10 8d 24 00 00 01 13 14 1f 10 8d 24 00 00 01 13 15 } //00 00 
	condition:
		any of ($a_*)
 
}
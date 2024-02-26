
rule Trojan_BAT_Crysan_SN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 09 28 e2 00 00 0a 03 09 03 6f 40 00 00 0a 5d 17 d6 28 e2 00 00 0a da 13 04 07 11 04 28 e3 00 00 0a 28 e4 00 00 0a 28 41 00 00 0a 0b 09 17 d6 0d 09 08 31 cb } //02 00 
		$a_01_1 = {24 66 31 39 33 36 31 31 66 2d 34 34 35 32 2d 34 32 63 30 2d 61 62 63 39 2d 39 62 31 34 66 65 39 62 63 36 33 66 } //00 00  $f193611f-4452-42c0-abc9-9b14fe9bc63f
	condition:
		any of ($a_*)
 
}
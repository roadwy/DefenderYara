
rule Trojan_BAT_Redline_GJI_MTB{
	meta:
		description = "Trojan:BAT/Redline.GJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6b 67 66 66 66 67 73 64 64 66 66 66 64 68 64 72 66 64 61 66 64 64 73 73 68 63 66 } //01 00  hkgfffgsddfffdhdrfdafddsshcf
		$a_01_1 = {73 64 64 64 64 66 66 66 68 65 64 66 67 64 64 6a 66 66 66 66 66 67 6a 66 73 66 6b 64 67 73 61 63 73 61 66 70 } //01 00  sddddfffhedfgddjfffffgjfsfkdgsacsafp
		$a_01_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  TripleDESCryptoServiceProvider
		$a_01_3 = {6e 68 66 66 73 6b 64 67 73 66 6b 64 66 66 66 64 64 61 64 66 72 66 66 66 64 64 68 66 73 63 66 64 66 } //00 00  nhffskdgsfkdfffddadfrfffddhfscfdf
	condition:
		any of ($a_*)
 
}
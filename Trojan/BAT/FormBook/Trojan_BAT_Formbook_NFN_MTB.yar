
rule Trojan_BAT_Formbook_NFN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 07 06 28 90 01 03 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_2 = {52 30 35 33 35 } //01 00  R0535
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //00 00  ColorTranslator
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_NFN_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 02 00 "
		
	strings :
		$a_81_0 = {75 68 62 75 6a 69 75 6a 68 6e 69 6e 68 6a 69 6b 69 75 68 } //02 00  uhbujiujhninhjikiuh
		$a_81_1 = {4f 53 4d 65 74 61 64 61 74 61 2e 48 61 73 68 45 6c 65 6d 65 6e 74 } //02 00  OSMetadata.HashElement
		$a_81_2 = {72 65 77 6a 6e 67 66 67 72 66 71 65 } //02 00  rewjngfgrfqe
		$a_81_3 = {6f 6b 6d 6e 6a 69 75 68 62 76 } //01 00  okmnjiuhbv
		$a_81_4 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_5 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_81_6 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //00 00  ColorTranslator
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_NFN_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 00 53 00 4d 00 65 00 74 00 61 00 64 00 61 00 74 00 61 00 2e 00 48 00 61 00 73 00 68 00 45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 } //01 00  OSMetadata.HashElement
		$a_01_1 = {52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f } //01 00  R3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrkto
		$a_01_2 = {2e 67 2e 72 65 73 6f 75 72 63 65 } //01 00  .g.resource
		$a_01_3 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_4 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_5 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_6 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_7 = {53 70 6c 69 74 } //00 00  Split
	condition:
		any of ($a_*)
 
}
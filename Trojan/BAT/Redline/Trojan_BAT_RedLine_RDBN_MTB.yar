
rule Trojan_BAT_RedLine_RDBN_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 50 6e 41 68 42 7a 51 6e 76 78 70 41 43 6d 61 71 65 73 6e 76 54 75 73 72 61 41 48 64 56 69 6a 42 6d 77 50 72 56 43 67 58 49 6c 4e 73 74 5f 49 5a } //1 RPnAhBzQnvxpACmaqesnvTusraAHdVijBmwPrVCgXIlNst_IZ
		$a_01_1 = {51 52 64 76 77 46 54 70 62 49 74 73 49 46 59 79 73 78 4f 6d 78 4e 66 54 51 74 41 52 4b 77 77 47 74 6c 47 5f 46 6a 51 73 4f 6a } //1 QRdvwFTpbItsIFYysxOmxNfTQtARKwwGtlG_FjQsOj
		$a_01_2 = {73 75 66 66 69 63 69 65 6e 74 } //1 sufficient
		$a_01_3 = {70 42 45 62 6c 49 72 44 66 52 77 79 4d 66 } //1 pBEblIrDfRwyMf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
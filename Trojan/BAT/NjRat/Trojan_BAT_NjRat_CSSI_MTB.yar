
rule Trojan_BAT_NjRat_CSSI_MTB{
	meta:
		description = "Trojan:BAT/NjRat.CSSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 06 28 08 00 00 06 6f 90 01 04 0d 2b 15 12 03 28 24 00 00 0a 13 04 11 04 28 06 00 00 06 de 03 26 de 00 12 03 28 25 00 00 0a 2d e2 90 00 } //5
		$a_01_1 = {54 68 54 64 75 5a 65 47 62 58 48 50 49 66 4e 79 42 4b 4b 66 69 4d 66 45 4e 49 62 54 43 } //1 ThTduZeGbXHPIfNyBKKfiMfENIbTC
		$a_01_2 = {57 5a 51 52 64 72 48 63 59 6f 46 63 7a 69 57 4e 67 4d 76 6a 48 6f 48 56 57 4c 50 66 } //1 WZQRdrHcYoFcziWNgMvjHoHVWLPf
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
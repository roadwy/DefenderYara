
rule Trojan_Win32_Redline_CAY_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {f6 17 80 2f d6 47 e2 } //01 00 
		$a_01_1 = {74 68 74 73 6b 74 6e 71 70 78 6a 79 6d 6c 69 62 72 66 65 6c 67 74 63 78 69 69 7a 68 70 68 6a 77 6b 6f } //01 00  thtsktnqpxjymlibrfelgtcxiizhphjwko
		$a_01_2 = {71 74 6e 63 66 76 74 64 73 75 78 63 6c 6d 65 64 69 68 73 66 68 6c 61 7a 6c 62 68 74 76 74 72 69 66 64 77 64 70 6a 71 6a 70 6d 6d 67 64 66 75 6d 66 6d 6d 6c 6b 6a 6c 6c 66 72 67 67 73 77 73 7a 75 6f 74 74 68 71 6c 67 77 65 74 69 63 } //01 00  qtncfvtdsuxclmedihsfhlazlbhtvtrifdwdpjqjpmmgdfumfmmlkjllfrggswszuotthqlgwetic
		$a_01_3 = {65 66 79 6d 7a 6b 64 79 62 63 69 71 76 73 6f 77 75 61 6d 63 6c 6c 69 70 6b 6a 6c 79 70 6e 6a 69 7a 65 67 6a 72 68 67 6c 64 66 76 6f 70 69 74 73 66 70 6a 71 6b 72 76 69 65 65 72 62 61 61 71 67 79 6e 6d 67 64 78 65 70 6b 71 66 6b 67 68 66 6b 6c 61 78 71 66 65 6b 7a 72 63 63 6c } //01 00  efymzkdybciqvsowuamcllipkjlypnjizegjrhgldfvopitsfpjqkrvieerbaaqgynmgdxepkqfkghfklaxqfekzrccl
		$a_01_4 = {61 6e 69 75 68 79 75 74 63 76 70 72 6f 63 65 6d 79 78 64 73 61 6d 6c 78 6c 78 68 77 7a 6c 61 63 6f 67 6d 64 } //00 00  aniuhyutcvprocemyxdsamlxlxhwzlacogmd
	condition:
		any of ($a_*)
 
}
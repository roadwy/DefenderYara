
rule Trojan_BAT_AveMariaRat_MW_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 68 77 73 6d 6e 76 72 78 78 64 73 64 71 72 74 6a 64 71 66 76 64 62 } //01 00  Phwsmnvrxxdsdqrtjdqfvdb
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //01 00  DynamicInvoke
		$a_01_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_4 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_5 = {3a 00 2f 00 2f 00 32 00 2e 00 35 00 38 00 2e 00 31 00 34 00 39 00 2e 00 32 00 2f 00 } //00 00  ://2.58.149.2/
	condition:
		any of ($a_*)
 
}
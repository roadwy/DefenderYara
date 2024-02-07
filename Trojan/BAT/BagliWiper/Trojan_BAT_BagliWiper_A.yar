
rule Trojan_BAT_BagliWiper_A{
	meta:
		description = "Trojan:BAT/BagliWiper.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 78 00 6c 00 73 00 78 00 } //01 00  .xlsx
		$a_01_1 = {42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 3a 00 } //01 00  Bitcoin address:
		$a_01_2 = {45 00 6d 00 61 00 69 00 6c 00 3a 00 } //01 00  Email:
		$a_01_3 = {71 00 64 00 69 00 6d 00 20 00 6f 00 6c 00 75 00 6e 00 61 00 6e 00 20 00 62 00 69 00 74 00 6b 00 6f 00 69 00 6e 00 20 00 61 00 64 00 72 00 65 00 73 00 69 00 6e 00 } //00 00  qdim olunan bitkoin adresin
	condition:
		any of ($a_*)
 
}
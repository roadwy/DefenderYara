
rule Trojan_BAT_Seraph_ASFO_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ASFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 65 67 72 76 75 73 63 78 63 70 6a 35 32 35 66 37 75 39 34 65 36 38 39 39 74 79 68 74 39 6c 34 } //01 00  kegrvuscxcpj525f7u94e6899tyht9l4
		$a_01_1 = {75 35 79 74 77 71 73 39 37 65 63 79 78 37 62 73 6e 68 74 6b 32 6c 32 68 76 38 34 6b 32 33 61 37 } //01 00  u5ytwqs97ecyx7bsnhtk2l2hv84k23a7
		$a_01_2 = {37 70 61 63 74 33 6b 75 6d 35 6d 7a 37 78 75 35 38 35 6b 79 74 62 77 70 6d 39 36 6d 35 78 68 6a } //01 00  7pact3kum5mz7xu585kytbwpm96m5xhj
		$a_01_3 = {6b 38 32 6c 68 74 6d 6a 33 77 61 76 78 74 64 64 78 6c 70 34 6e 32 6e 32 33 67 66 6a 74 6a 34 6e } //01 00  k82lhtmj3wavxtddxlp4n2n23gfjtj4n
		$a_01_4 = {33 66 37 33 73 6a 70 68 74 6e 35 6c 62 36 37 36 74 7a 37 32 79 77 67 33 68 37 67 6c 6c 76 37 6e } //01 00  3f73sjphtn5lb676tz72ywg3h7gllv7n
		$a_01_5 = {36 38 6a 32 63 6e 37 6b 34 6b 61 64 34 63 65 6a 63 68 7a 62 61 35 67 32 33 78 6d 32 68 36 37 72 } //01 00  68j2cn7k4kad4cejchzba5g23xm2h67r
		$a_01_6 = {38 72 32 62 74 75 34 39 65 79 76 32 6d 35 6b 36 66 6b 32 33 36 35 32 34 79 70 37 78 32 75 73 72 } //01 00  8r2btu49eyv2m5k6fk236524yp7x2usr
		$a_01_7 = {32 35 63 6e 6c 6e 7a 65 6e 79 74 77 73 66 6d 68 65 78 74 71 38 36 6e 63 6d 68 65 68 67 63 65 75 } //00 00  25cnlnzenytwsfmhextq86ncmhehgceu
	condition:
		any of ($a_*)
 
}
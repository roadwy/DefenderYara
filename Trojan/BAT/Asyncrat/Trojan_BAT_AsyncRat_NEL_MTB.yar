
rule Trojan_BAT_AsyncRat_NEL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 32 36 65 30 61 37 64 36 2d 64 64 35 39 2d 34 37 64 30 2d 39 32 62 34 2d 35 32 31 39 61 64 31 38 35 65 33 38 } //05 00  $26e0a7d6-dd59-47d0-92b4-5219ad185e38
		$a_01_1 = {79 66 36 49 57 46 4e 7a 53 45 65 72 53 4f 39 5a 35 47 78 } //02 00  yf6IWFNzSEerSO9Z5Gx
		$a_01_2 = {6c 00 6f 00 67 00 73 00 5f 00 71 00 75 00 69 00 63 00 6b 00 5f 00 } //02 00  logs_quick_
		$a_01_3 = {72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 73 00 54 00 6f 00 6f 00 6c 00 } //02 00  runningProcessesTool
		$a_01_4 = {48 43 53 20 43 6f 6d 70 75 74 65 72 73 20 26 20 4c 61 70 74 6f 70 73 } //02 00  HCS Computers & Laptops
		$a_01_5 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 5f 00 67 00 72 00 61 00 70 00 68 00 5f 00 63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00 } //00 00  processor_graph_container
	condition:
		any of ($a_*)
 
}
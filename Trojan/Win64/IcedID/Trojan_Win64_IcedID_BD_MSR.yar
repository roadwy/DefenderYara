
rule Trojan_Win64_IcedID_BD_MSR{
	meta:
		description = "Trojan:Win64/IcedID.BD!MSR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 6f 78 56 47 78 55 68 4d 53 33 37 75 35 } //02 00  AoxVGxUhMS37u5
		$a_01_1 = {44 53 76 57 6a 63 4c 6e 30 74 } //02 00  DSvWjcLn0t
		$a_01_2 = {48 36 73 6d 6b 6f 43 77 49 6e } //02 00  H6smkoCwIn
		$a_01_3 = {4b 75 32 45 71 41 31 } //02 00  Ku2EqA1
		$a_01_4 = {50 35 33 67 76 73 } //02 00  P53gvs
		$a_01_5 = {59 58 53 42 77 45 38 64 71 76 59 } //02 00  YXSBwE8dqvY
		$a_01_6 = {67 45 7a 37 78 59 75 51 6f } //02 00  gEz7xYuQo
		$a_01_7 = {6c 69 69 7a 56 46 51 } //00 00  liizVFQ
	condition:
		any of ($a_*)
 
}
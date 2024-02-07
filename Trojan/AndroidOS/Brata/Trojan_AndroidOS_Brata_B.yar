
rule Trojan_AndroidOS_Brata_B{
	meta:
		description = "Trojan:AndroidOS/Brata.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 61 63 74 64 65 76 6d 61 6e 67 } //01 00  startactdevmang
		$a_00_1 = {73 74 61 72 74 61 63 74 67 70 70 65 72 } //01 00  startactgpper
		$a_00_2 = {73 74 61 72 74 61 63 74 6f 76 65 72 6c 61 79 } //01 00  startactoverlay
		$a_00_3 = {73 74 61 72 74 73 6d 73 70 65 72 6d 6e 65 77 } //01 00  startsmspermnew
		$a_00_4 = {73 74 61 72 74 61 63 74 77 72 69 74 65 73 79 } //01 00  startactwritesy
		$a_00_5 = {73 74 61 72 74 73 63 72 65 65 6e 63 61 70 } //01 00  startscreencap
		$a_00_6 = {74 61 6b 65 73 63 72 65 65 6e 73 68 6f 74 } //01 00  takescreenshot
		$a_00_7 = {74 72 61 63 6b 67 67 70 70 73 73 } //00 00  trackggppss
	condition:
		any of ($a_*)
 
}
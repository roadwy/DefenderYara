
rule Trojan_MacOS_OpinionSpy_F_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 61 6d 70 61 69 67 6e 69 64 2e 74 78 74 } //01 00  campaignid.txt
		$a_00_1 = {74 6d 70 2f 70 6f 44 65 6d 6f 2e 74 78 74 } //01 00  tmp/poDemo.txt
		$a_00_2 = {4d 61 63 4d 65 74 65 72 32 2f 74 72 75 6e 6b 2f 4d 61 63 41 6e 61 6c 79 73 65 72 2f 61 6c 67 6f 72 69 74 68 6d 2f } //01 00  MacMeter2/trunk/MacAnalyser/algorithm/
		$a_00_3 = {64 70 64 2e 73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //00 00  dpd.securestudies.com
		$a_00_4 = {5d 04 00 } //00 0f 
	condition:
		any of ($a_*)
 
}
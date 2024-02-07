
rule Trojan_AndroidOS_DownSMS_A{
	meta:
		description = "Trojan:AndroidOS/DownSMS.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 6d 4d 74 54 73 53 5d 2a } //01 00  [mMtTsS]*
		$a_01_1 = {5b 62 42 65 45 65 45 5d 2a } //01 00  [bBeEeE]*
		$a_01_2 = {44 45 46 31 37 37 33 } //01 00  DEF1773
		$a_01_3 = {41 63 74 69 76 61 74 6f 72 41 63 74 69 76 69 74 79 } //01 00  ActivatorActivity
		$a_01_4 = {d0 9e d1 88 d0 b8 d0 b1 d0 ba d0 b0 20 d0 bf d1 80 d0 b8 20 d0 b7 d0 b0 d0 b3 d1 80 d1 83 d0 b7 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_AndroidOS_FakeNeflick_A{
	meta:
		description = "Trojan:AndroidOS/FakeNeflick.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 72 6f 66 6f 6c 69 6f 2e 6e 6f 2d 69 70 2e 62 69 7a 2f 6c 6f 67 69 6e 2e 70 68 70 } //01 00  erofolio.no-ip.biz/login.php
		$a_01_1 = {59 6f 75 72 20 41 6e 64 72 6f 69 64 20 54 56 20 69 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 65 64 } //01 00  Your Android TV is not supported
		$a_01_2 = {6e 65 74 66 6c 69 78 5f 62 6b 67 } //01 00  netflix_bkg
		$a_01_3 = {77 65 62 53 65 72 76 65 72 41 6e 73 77 65 72 } //00 00  webServerAnswer
	condition:
		any of ($a_*)
 
}
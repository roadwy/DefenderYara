
rule Trojan_Win32_Adclicker_AK{
	meta:
		description = "Trojan:Win32/Adclicker.AK,SIGNATURE_TYPE_PEHSTR,36 01 31 01 18 00 00 64 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //64 00  InternetCrackUrlA
		$a_01_1 = {32 30 32 2e 36 37 2e 32 32 30 2e 32 31 39 2f 74 72 61 66 63 2d 32 2f 72 66 65 2e 70 68 70 } //64 00  202.67.220.219/trafc-2/rfe.php
		$a_01_2 = {31 44 41 45 46 43 42 39 2d 30 36 43 38 2d 34 37 63 36 2d 38 46 32 30 2d 33 46 42 35 34 42 32 34 34 44 41 41 } //01 00  1DAEFCB9-06C8-47c6-8F20-3FB54B244DAA
		$a_01_3 = {73 65 61 72 63 68 2e 61 62 6f 75 74 2e 63 6f 6d } //01 00  search.about.com
		$a_01_4 = {73 65 61 72 63 68 2e 61 6f 6c 2e 63 6f } //01 00  search.aol.co
		$a_01_5 = {73 65 61 72 63 68 2e 61 73 69 61 63 6f 2e 63 6f 6d } //01 00  search.asiaco.com
		$a_01_6 = {73 65 61 72 63 68 2e 64 61 75 6d 2e 6e 65 74 } //01 00  search.daum.net
		$a_01_7 = {73 65 61 72 63 68 2e 64 6d 6f 7a 2e 6f 72 67 } //01 00  search.dmoz.org
		$a_01_8 = {73 65 61 72 63 68 2e 65 61 72 74 68 6c 69 6e 6b 2e 6e 65 74 } //01 00  search.earthlink.net
		$a_01_9 = {73 65 61 72 63 68 2e 67 6f 68 69 70 2e 63 6f 6d } //01 00  search.gohip.com
		$a_01_10 = {73 65 61 72 63 68 2e 6c 6f 6f 6b 73 6d 61 72 74 2e 63 6f 6d } //01 00  search.looksmart.com
		$a_01_11 = {73 65 61 72 63 68 2e 6c 79 63 6f 73 2e 63 6f 2e 75 6b } //01 00  search.lycos.co.uk
		$a_01_12 = {73 65 61 72 63 68 2e 6c 79 63 6f 73 2e 63 6f 6d } //01 00  search.lycos.com
		$a_01_13 = {73 65 61 72 63 68 2e 6d 73 6e 2e 63 6f } //01 00  search.msn.co
		$a_01_14 = {73 65 61 72 63 68 2e 6d 73 6e 2e 66 72 } //01 00  search.msn.fr
		$a_01_15 = {73 65 61 72 63 68 2e 6e 65 74 73 63 61 70 65 2e 63 6f 6d } //01 00  search.netscape.com
		$a_01_16 = {73 65 61 72 63 68 2e 6e 65 74 7a 65 72 6f 2e 6e 65 74 } //01 00  search.netzero.net
		$a_01_17 = {73 65 61 72 63 68 2e 73 79 6d 70 61 74 69 63 6f 2e 6d 73 6e 2e 63 61 } //01 00  search.sympatico.msn.ca
		$a_01_18 = {73 65 61 72 63 68 2e 77 61 6e 61 64 6f 6f 2e 63 6f 2e 75 6b } //01 00  search.wanadoo.co.uk
		$a_01_19 = {73 65 61 72 63 68 2e 78 74 72 61 6d 73 6e 2e 63 6f 2e 6e 7a } //01 00  search.xtramsn.co.nz
		$a_01_20 = {73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f } //01 00  search.yahoo.co
		$a_01_21 = {73 65 61 72 63 68 66 65 65 64 2e 63 6f 6d } //01 00  searchfeed.com
		$a_01_22 = {73 65 61 72 63 68 6d 69 72 61 63 6c 65 2e 63 6f 6d } //01 00  searchmiracle.com
		$a_01_23 = {73 65 61 72 63 68 73 63 6f 75 74 2e 63 6f 6d } //00 00  searchscout.com
	condition:
		any of ($a_*)
 
}
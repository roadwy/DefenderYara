
rule Trojan_BAT_NjRat_NEBS_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {64 31 30 65 34 63 39 61 2d 31 38 38 35 2d 34 64 34 39 2d 38 34 38 33 2d 34 32 31 34 66 35 36 38 31 61 36 62 } //05 00  d10e4c9a-1885-4d49-8483-4214f5681a6b
		$a_01_1 = {64 66 67 73 67 73 66 35 36 33 36 35 33 2e 70 64 62 } //05 00  dfgsgsf563653.pdb
		$a_01_2 = {5a 00 47 00 5a 00 6e 00 63 00 32 00 64 00 7a 00 5a 00 6a 00 55 00 32 00 4d 00 7a 00 59 00 31 00 4d 00 79 00 55 00 3d 00 } //03 00  ZGZnc2dzZjU2MzY1MyU=
		$a_01_3 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 } //01 00  CryptoObfuscator_Output
		$a_01_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerHiddenAttribute
	condition:
		any of ($a_*)
 
}
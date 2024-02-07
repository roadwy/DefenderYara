
rule Trojan_BAT_DCRat_F_MTB{
	meta:
		description = "Trojan:BAT/DCRat.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 00 55 00 75 00 6b 00 72 00 62 00 } //02 00  xUukrb
		$a_01_1 = {46 74 4f 48 4b 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //02 00  FtOHK.g.resources
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}
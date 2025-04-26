
rule Trojan_MacOS_Rustbucket_AQ{
	meta:
		description = "Trojan:MacOS/Rustbucket.AQ,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 6f 20 45 72 72 6f 72 43 68 65 63 6b 2e 7a 69 70 } //1 -o ErrorCheck.zip
		$a_00_1 = {64 6f 77 6e 5f 75 70 64 61 74 65 5f 72 75 6e } //1 down_update_run
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
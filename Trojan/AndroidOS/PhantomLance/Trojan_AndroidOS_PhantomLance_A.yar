
rule Trojan_AndroidOS_PhantomLance_A{
	meta:
		description = "Trojan:AndroidOS/PhantomLance.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 4d 53 5f 41 43 54 49 56 49 54 59 } //02 00  .MS_ACTIVITY
		$a_00_1 = {78 70 6f 69 68 68 64 65 63 76 64 64 } //02 00  xpoihhdecvdd
		$a_00_2 = {44 52 4f 50 20 54 41 42 4c 45 20 49 46 20 45 58 49 53 54 53 20 69 64 68 67 78 6f 6e 79 67 39 79 68 6e } //00 00  DROP TABLE IF EXISTS idhgxonyg9yhn
		$a_00_3 = {5d 04 00 00 } //ee 92 
	condition:
		any of ($a_*)
 
}
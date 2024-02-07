
rule Trojan_BAT_Injector_SS_bit{
	meta:
		description = "Trojan:BAT/Injector.SS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6d 00 61 00 74 00 61 00 32 00 2e 00 62 00 61 00 74 00 90 02 20 64 00 61 00 73 00 69 00 6f 00 68 00 6e 00 64 00 61 00 73 00 64 00 61 00 73 00 64 00 90 00 } //01 00 
		$a_01_1 = {23 00 6e 00 65 00 77 00 74 00 6d 00 70 00 23 00 24 00 24 00 24 00 2e 00 65 00 78 00 65 00 24 00 24 00 24 00 } //01 00  #newtmp#$$$.exe$$$
		$a_01_2 = {66 00 73 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 } //00 00  fsfsdfsdfsdfsdf
	condition:
		any of ($a_*)
 
}

rule Trojan_AndroidOS_BankerAgent_A{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {4b 45 59 5f 55 50 4c 4f 41 44 5f 31 } //02 00 
		$a_00_1 = {4b 45 59 5f 54 45 4c 45 43 4f 4d 53 5f 4e 41 4d 45 } //02 00 
		$a_00_2 = {35 48 36 2b 50 6a 71 37 30 4f 34 75 73 51 36 37 4b 75 50 77 77 77 3d 3d } //00 00 
		$a_00_3 = {5d 04 00 00 } //f6 be 
	condition:
		any of ($a_*)
 
}
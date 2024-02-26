
rule Trojan_AndroidOS_Teardroid_A{
	meta:
		description = "Trojan:AndroidOS/Teardroid.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 22 73 75 63 63 65 73 73 22 3a 74 72 75 65 7d } //01 00  {"success":true}
		$a_01_1 = {7b 22 65 72 72 6f 72 22 3a 22 4e 6f 20 63 6f 6e 74 61 63 74 20 66 6f 75 6e 64 21 22 7d } //00 00  {"error":"No contact found!"}
	condition:
		any of ($a_*)
 
}
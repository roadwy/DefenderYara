
rule Trojan_AndroidOS_Spynote_C{
	meta:
		description = "Trojan:AndroidOS/Spynote.C,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 59 5f 56 50 4e 5f 4e 4f 54 49 46 49 43 41 54 49 4f 4e 5f 49 44 } //01 00  MY_VPN_NOTIFICATION_ID
		$a_01_1 = {74 6f 20 42 6c 6f 63 6b 20 61 70 70 2c 20 64 69 73 61 62 6c 65 20 66 69 72 65 77 61 6c 6c 20 66 69 72 73 74 } //00 00  to Block app, disable firewall first
	condition:
		any of ($a_*)
 
}
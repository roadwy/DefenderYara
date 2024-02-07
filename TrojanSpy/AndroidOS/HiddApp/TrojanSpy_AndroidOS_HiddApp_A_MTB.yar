
rule TrojanSpy_AndroidOS_HiddApp_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/HiddApp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 73 6b 79 73 70 6c 6f 69 74 2f 50 61 79 6c 6f 61 64 73 } //01 00  com/example/skysploit/Payloads
		$a_00_1 = {68 69 64 65 41 70 70 49 63 6f 6e } //03 00  hideAppIcon
		$a_00_2 = {61 70 61 79 61 2d 32 35 32 36 33 2e 70 6f 72 74 6d 61 70 2e 69 6f } //01 00  apaya-25263.portmap.io
		$a_00_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //00 00  content://call_log/calls
		$a_00_4 = {5d 04 00 } //00 2c 
	condition:
		any of ($a_*)
 
}
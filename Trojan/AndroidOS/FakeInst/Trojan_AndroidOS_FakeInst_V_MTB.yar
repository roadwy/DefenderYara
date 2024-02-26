
rule Trojan_AndroidOS_FakeInst_V_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 72 6f 6f 6c 73 64 69 73 70 6c 61 79 } //01 00  setroolsdisplay
		$a_01_1 = {72 6f 6f 6c 73 2e 74 78 74 } //01 00  rools.txt
		$a_01_2 = {63 6f 6d 2f 75 6e 69 70 6c 75 67 69 6e 2f 73 65 6e 64 65 72 } //01 00  com/uniplugin/sender
		$a_01_3 = {2f 73 74 61 74 73 2f 61 64 76 2e 70 68 70 } //01 00  /stats/adv.php
		$a_01_4 = {73 65 6e 64 53 4d 53 6b 69 } //00 00  sendSMSki
	condition:
		any of ($a_*)
 
}
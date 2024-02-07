
rule Trojan_AndroidOS_Opfake_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 78 25 62 25 6f 25 74 25 30 25 30 25 37 25 } //01 00  %x%b%o%t%0%0%7%
		$a_01_1 = {62 6e 2f 73 61 76 65 5f 6d 65 73 73 61 67 65 2e 70 68 70 } //01 00  bn/save_message.php
		$a_01_2 = {23 6d 23 65 23 73 23 23 73 23 61 23 67 23 65 23 } //01 00  #m#e#s##s#a#g#e#
		$a_01_3 = {63 6f 6d 2f 74 75 6a 74 72 2f 72 74 62 72 72 2f 61 64 6d 5f 72 65 63 69 76 } //01 00  com/tujtr/rtbrr/adm_reciv
		$a_01_4 = {2f 62 6e 2f 72 65 67 2e 70 68 70 3f } //00 00  /bn/reg.php?
	condition:
		any of ($a_*)
 
}
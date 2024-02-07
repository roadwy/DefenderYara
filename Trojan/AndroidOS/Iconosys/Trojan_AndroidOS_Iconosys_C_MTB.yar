
rule Trojan_AndroidOS_Iconosys_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Iconosys.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 72 65 70 6c 69 65 72 2e 6e 65 74 2f 73 6d 73 72 65 70 6c 79 } //01 00  smsreplier.net/smsreply
		$a_01_1 = {74 72 69 63 6b 65 72 64 61 74 61 2e 70 68 70 } //01 00  trickerdata.php
		$a_01_2 = {70 68 6f 6e 65 64 61 74 61 6e 65 77 2e 70 68 70 } //01 00  phonedatanew.php
		$a_01_3 = {73 65 6e 64 6c 69 63 65 6e 63 65 2e 70 68 70 } //01 00  sendlicence.php
		$a_01_4 = {53 65 6e 64 42 6b 70 } //00 00  SendBkp
	condition:
		any of ($a_*)
 
}
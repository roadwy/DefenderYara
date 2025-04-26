
rule Trojan_AndroidOS_SAgnt_AU_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AU!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 5f 73 65 6e 64 5f 63 6f 6e 74 65 6e 74 73 } //1 sys_send_contents
		$a_01_1 = {73 79 73 5f 73 61 76 65 64 5f 63 6f 6e 74 65 6e 74 73 } //1 sys_saved_contents
		$a_01_2 = {53 65 74 54 6e 6b 54 72 61 63 6b 65 72 } //1 SetTnkTracker
		$a_01_3 = {2f 61 66 66 6d 6f 62 2e 74 6f 72 6e 69 6b 61 2e 63 6f 6d 2f 73 65 72 76 69 63 65 5f 6c 69 62 2e 70 68 70 } //1 /affmob.tornika.com/service_lib.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
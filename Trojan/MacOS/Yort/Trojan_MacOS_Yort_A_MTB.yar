
rule Trojan_MacOS_Yort_A_MTB{
	meta:
		description = "Trojan:MacOS/Yort.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 6f 77 69 6e 67 6f 70 65 72 61 74 69 6f 6e 73 2e 63 6f 6d 2f 63 68 61 74 2f 63 68 61 74 2e 70 68 70 } //2 towingoperations.com/chat/chat.php
		$a_00_1 = {62 61 73 65 62 61 6c 6c 63 68 61 72 6c 65 6d 61 67 6e 65 6c 65 67 61 72 64 65 75 72 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 6c 61 6e 67 75 61 67 65 73 2f 63 6f 6d 6d 6f 6e 2e 70 68 70 } //1 baseballcharlemagnelegardeur.com/wp-content/languages/common.php
		$a_00_2 = {74 61 6e 67 6f 77 69 74 68 63 6f 6c 65 74 74 65 2e 63 6f 6d 2f 70 61 67 65 73 2f 63 6f 6d 6d 6f 6e 2e 70 68 70 } //1 tangowithcolette.com/pages/common.php
		$a_00_3 = {52 65 70 6c 79 54 72 6f 79 49 6e 66 6f } //1 ReplyTroyInfo
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
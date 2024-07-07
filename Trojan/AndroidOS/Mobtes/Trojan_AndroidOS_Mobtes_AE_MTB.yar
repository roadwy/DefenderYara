
rule Trojan_AndroidOS_Mobtes_AE_MTB{
	meta:
		description = "Trojan:AndroidOS/Mobtes.AE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 6d 73 72 65 70 6c 69 65 72 2e 6e 65 74 2f 73 6d 73 72 65 70 6c 79 } //1 smsreplier.net/smsreply
		$a_00_1 = {74 72 69 63 6b 65 72 64 61 74 61 2e 70 68 70 } //1 trickerdata.php
		$a_00_2 = {3a 2f 2f 64 65 74 61 69 6c 73 3f 69 64 3d 63 6f 6d 2e 73 61 6e 74 61 2e 69 63 6f 6e 6f 73 79 73 } //1 ://details?id=com.santa.iconosys
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
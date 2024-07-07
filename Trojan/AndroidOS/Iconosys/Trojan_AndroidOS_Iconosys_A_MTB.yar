
rule Trojan_AndroidOS_Iconosys_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Iconosys.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {62 6c 61 63 6b 66 6c 79 64 61 79 2e 63 6f 6d 2f 6e 65 77 } //1 blackflyday.com/new
		$a_00_1 = {4d 65 49 6e 4a 61 69 6c } //1 MeInJail
		$a_00_2 = {74 72 69 63 6b 65 72 64 61 74 61 2e 70 68 70 } //1 trickerdata.php
		$a_00_3 = {73 6d 73 72 65 70 6c 69 65 72 2e 6e 65 74 2f 73 6d 73 72 65 70 6c 79 } //1 smsreplier.net/smsreply
		$a_00_4 = {62 75 7a 7a 67 65 6f 64 61 74 61 2e 70 68 70 } //1 buzzgeodata.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
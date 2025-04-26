
rule Trojan_AndroidOS_Iconosys_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Iconosys.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 72 6b 65 74 3a 2f 2f 64 65 74 61 69 6c 73 3f 69 64 3d 63 6f 6d 2e 73 61 6e 74 61 2e 69 63 6f 6e 6f 73 79 73 } //1 market://details?id=com.santa.iconosys
		$a_01_1 = {6e 65 77 79 65 61 72 62 75 7a 7a 65 72 73 74 61 74 65 73 } //1 newyearbuzzerstates
		$a_01_2 = {73 6d 73 72 65 70 6c 61 79 69 65 72 73 74 61 74 65 73 } //1 smsreplayierstates
		$a_01_3 = {74 72 69 63 6b 74 72 61 63 6b 65 72 73 74 61 74 65 73 } //1 tricktrackerstates
		$a_01_4 = {73 6d 73 72 65 70 6c 69 65 72 2e 6e 65 74 2f 73 6d 73 72 65 70 6c 79 2f } //1 smsreplier.net/smsreply/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
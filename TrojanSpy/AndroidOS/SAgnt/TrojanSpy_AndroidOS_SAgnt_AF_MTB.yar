
rule TrojanSpy_AndroidOS_SAgnt_AF_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6d 72 34 34 34 5f 68 61 63 6b } //1 amr444_hack
		$a_01_1 = {5f 69 6e 66 6f 64 65 76 69 63 65 } //1 _infodevice
		$a_01_2 = {61 70 69 2e 64 62 2d 69 70 2e 63 6f 6d 2f 76 32 2f 66 72 65 65 2f 73 65 6c 66 } //1 api.db-ip.com/v2/free/self
		$a_01_3 = {5f 67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 _getAllContacts
		$a_01_4 = {5f 68 61 63 6b 65 72 5f 63 68 69 6c 64 5f 6c 69 73 74 65 6e 65 72 } //1 _hacker_child_listener
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
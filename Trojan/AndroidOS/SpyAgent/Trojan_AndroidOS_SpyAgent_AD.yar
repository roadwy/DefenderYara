
rule Trojan_AndroidOS_SpyAgent_AD{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AD,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 73 4c 69 73 74 } //1 callsList
		$a_01_1 = {44 65 6c 65 74 69 6e 67 20 43 6f 6e 76 65 72 73 61 74 69 6f 6e 20 50 6c 65 61 73 65 20 77 61 69 74 } //1 Deleting Conversation Please wait
		$a_01_2 = {55 70 6c 6f 61 64 69 6e 67 20 56 69 64 65 6f } //1 Uploading Video
		$a_01_3 = {50 6c 65 61 73 65 20 70 72 6f 76 69 64 65 20 74 68 65 20 70 65 72 6d 69 73 73 69 6f 6e 20 74 6f 20 77 6f 72 6b 20 70 72 6f 70 65 72 6c 79 } //1 Please provide the permission to work properly
		$a_01_4 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 70 64 32 6c 73 62 48 4e 6c 59 33 56 79 5a 58 6c 76 64 53 35 6a 62 32 30 76 } //1 aHR0cDovL3d3dy5pd2lsbHNlY3VyZXlvdS5jb20v
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
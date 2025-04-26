
rule Trojan_BAT_AveMariaRAT_NYT_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 73 6f 67 67 73 73 73 73 73 67 67 67 67 67 67 67 6d 65 64 69 72 65 63 74 6f 72 79 } //1 C:\soggsssssgggggggmedirectory
		$a_81_1 = {43 3a 5c 73 6f 6d 66 66 66 66 66 66 66 66 66 66 66 65 64 69 72 65 63 74 6f 72 79 } //1 C:\somfffffffffffedirectory
		$a_81_2 = {53 73 75 63 67 67 73 73 68 68 68 67 64 64 64 64 64 64 64 73 64 64 64 64 66 63 63 67 67 64 66 73 64 65 66 73 73 } //1 Ssucggsshhhgdddddddsddddfccggdfsdefss
		$a_81_3 = {66 6a 66 66 63 66 73 66 6b 66 68 67 6a } //1 fjffcfsfkfhgj
		$a_81_4 = {67 64 64 66 64 73 68 73 66 64 67 68 } //1 gddfdshsfdgh
		$a_81_5 = {68 6a 66 66 73 63 66 66 6b 68 6a } //1 hjffscffkhj
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
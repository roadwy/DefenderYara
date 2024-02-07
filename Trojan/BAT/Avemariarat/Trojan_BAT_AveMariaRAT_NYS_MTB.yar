
rule Trojan_BAT_AveMariaRAT_NYS_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 73 6f 67 67 73 73 73 73 73 67 67 67 67 67 67 67 6d 65 64 69 72 65 63 74 6f 72 79 } //01 00  C:\soggsssssgggggggmedirectory
		$a_81_1 = {43 3a 5c 4e 65 64 64 73 73 73 73 73 73 73 73 73 73 73 73 73 73 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 77 54 65 6d 70 } //01 00  C:\NeddssssssssssssssddddddddddddddddddddwTemp
		$a_81_2 = {66 6a 66 66 63 66 73 66 6b 66 68 67 6a } //01 00  fjffcfsfkfhgj
		$a_81_3 = {67 64 64 66 64 73 68 73 66 64 67 68 } //01 00  gddfdshsfdgh
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_5 = {68 6b 66 73 66 66 68 68 63 66 } //00 00  hkfsffhhcf
	condition:
		any of ($a_*)
 
}
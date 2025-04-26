
rule Trojan_BAT_Remcos_NM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 18 da 0b 73 46 00 00 0a 0c 07 0d 16 13 04 } //5
		$a_81_1 = {77 31 32 34 37 32 38 5f 4e 65 77 5f 54 65 78 74 5f 44 6f 63 75 6d 65 6e 74 2e 74 78 74 } //1 w124728_New_Text_Document.txt
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 69 6d 67 75 72 6c 2e 69 72 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //1 https://imgurl.ir/download.php
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}
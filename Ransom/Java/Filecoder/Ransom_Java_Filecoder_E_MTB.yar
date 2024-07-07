
rule Ransom_Java_Filecoder_E_MTB{
	meta:
		description = "Ransom:Java/Filecoder.E!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 5f 52 61 6e 73 6f 6d 77 61 72 65 5f 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 set_Ransomware_Configuration
		$a_00_1 = {50 72 65 70 61 74 65 5f 4b 65 79 5f 46 6f 72 5f 45 6e 63 72 79 70 74 69 6f 6e } //1 Prepate_Key_For_Encryption
		$a_00_2 = {2e 52 61 6e 73 6f 6d 6b 65 79 } //1 .Ransomkey
		$a_00_3 = {4d 61 69 6e 5f 52 61 6e 73 6f 6d 77 61 72 65 5f 53 74 75 62 } //1 Main_Ransomware_Stub
		$a_00_4 = {68 61 63 6b 65 72 5f 64 61 74 61 } //1 hacker_data
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}

rule Ransom_Java_Filecoder_PA_MTB{
	meta:
		description = "Ransom:Java/Filecoder.PA!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 4e 6f 20 42 49 54 43 4f 49 4e 20 53 69 72 20 2c 20 59 6f 75 72 20 46 69 6c 65 73 20 41 72 65 20 54 6f 75 67 68 6c 79 20 45 6e 63 72 79 70 74 65 64 } //1 CNo BITCOIN Sir , Your Files Are Toughly Encrypted
		$a_01_1 = {73 65 74 5f 52 61 6e 73 6f 6d 77 61 72 65 5f 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 set_Ransomware_Configuration
		$a_01_2 = {50 72 65 70 61 74 65 5f 4b 65 79 5f 46 6f 72 5f 45 6e 63 72 79 70 74 69 6f 6e } //1 Prepate_Key_For_Encryption
		$a_01_3 = {2e 52 61 6e 73 6f 6d 6b 65 79 } //1 .Ransomkey
		$a_01_4 = {48 61 63 6b 65 72 44 61 74 61 2f 52 41 54 } //1 HackerData/RAT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
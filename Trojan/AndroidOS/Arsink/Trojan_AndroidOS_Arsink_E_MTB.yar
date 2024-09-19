
rule Trojan_AndroidOS_Arsink_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 61 72 6b 52 41 54 } //1 DarkRAT
		$a_01_1 = {5f 67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 _getAllContacts
		$a_01_2 = {55 73 65 72 5f 41 70 70 2e 74 78 74 } //1 User_App.txt
		$a_01_3 = {67 65 74 41 6c 6c 43 61 6c 6c 73 48 69 73 74 6f 74 79 } //1 getAllCallsHistoty
		$a_01_4 = {6d 6f 73 74 61 66 61 2f 6d 6f 73 74 61 66 61 31 2f 42 61 63 6b 53 65 72 76 69 63 65 73 } //1 mostafa/mostafa1/BackServices
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
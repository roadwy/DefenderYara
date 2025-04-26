
rule Trojan_BAT_Formbook_DV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {4d 65 64 69 63 61 6c 5f 4c 61 62 6f 72 61 74 6f 72 79 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Medical_Laboratory.My.Resources
		$a_81_1 = {4d 65 64 69 63 61 6c 5f 4c 61 62 6f 72 61 74 6f 72 79 2e 42 69 6c 6c 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Medical_Laboratory.Bills.resources
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_3 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_4 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_5 = {48 6f 74 70 6c 61 74 65 73 } //1 Hotplates
		$a_81_6 = {64 6e 73 70 79 } //1 dnspy
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_BAT_Formbook_DV_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {54 61 62 6c 65 41 64 61 70 74 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 TableAdapter.My.Resources
		$a_81_1 = {54 61 62 6c 65 41 64 61 70 74 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TableAdapter.Resources.resources
		$a_81_2 = {67 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 get_ConnectionString
		$a_81_3 = {49 6e 74 65 72 6c 6f 63 6b 65 64 } //1 Interlocked
		$a_81_4 = {69 73 4c 4f 53 42 6c 6f 63 6b 69 6e 67 } //1 isLOSBlocking
		$a_81_5 = {70 73 79 6b 65 72 70 6f 77 65 72 73 } //1 psykerpowers
		$a_81_6 = {43 61 6e 6f 6e } //1 Canon
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_BAT_Formbook_DV_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {51 75 4e 65 63 74 52 61 7a 6f 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 QuNectRazor.My.Resources
		$a_81_1 = {51 75 4e 65 63 74 52 61 7a 6f 72 2e 66 72 6d 52 61 7a 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //1 QuNectRazor.frmRazor.resources
		$a_81_2 = {63 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 connectionString
		$a_81_3 = {72 61 7a 6f 72 5f 4c 6f 61 64 } //1 razor_Load
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {53 6f 61 70 4e 6d 74 6f 6b 65 6e } //1 SoapNmtoken
		$a_81_6 = {67 65 74 5f 44 69 72 65 63 74 6f 72 79 } //1 get_Directory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
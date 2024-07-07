
rule Trojan_BAT_Formbook_ET_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 39 66 61 65 36 30 65 62 2d 39 35 35 32 2d 34 33 61 37 2d 62 37 65 35 2d 64 64 33 33 32 39 38 63 35 37 64 61 } //20 $9fae60eb-9552-43a7-b7e5-dd33298c57da
		$a_81_1 = {24 32 63 61 65 34 35 32 36 2d 64 66 64 35 2d 34 66 31 31 2d 61 65 32 65 2d 65 62 33 35 30 64 66 34 32 36 39 31 } //20 $2cae4526-dfd5-4f11-ae2e-eb350df42691
		$a_81_2 = {44 41 4e 47 5f 4e 48 41 50 5f 46 4f 52 4d } //1 DANG_NHAP_FORM
		$a_81_3 = {54 61 72 67 65 74 46 72 61 6d 65 77 6f 72 6b 41 74 74 72 69 62 75 74 65 } //1 TargetFrameworkAttribute
		$a_81_4 = {67 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 get_ConnectionString
		$a_81_5 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=25
 
}
rule Trojan_BAT_Formbook_ET_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {4b 65 79 65 64 43 6f 6c 6c 65 63 74 69 6f 6e 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 KeyedCollection.My.Resources
		$a_81_1 = {4b 65 79 65 64 43 6f 6c 6c 65 63 74 69 6f 6e 2e 50 65 6e 64 69 6e 67 57 4f 2e 72 65 73 6f 75 72 63 65 73 } //1 KeyedCollection.PendingWO.resources
		$a_81_2 = {44 61 68 6c 6b 65 6d 70 65 72 } //1 Dahlkemper
		$a_81_3 = {50 6f 77 65 72 20 54 72 61 6e 73 66 6f 72 6d 65 72 } //1 Power Transformer
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}

rule Trojan_Win64_ClipBanker_Z_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6c 74 5f 76 61 6c 75 65 5f 63 6c 69 70 70 65 72 64 65 66 61 75 6c 74 5f 76 61 6c 75 65 5f 63 6c 50 } //1 lt_value_clipperdefault_value_clP
		$a_81_1 = {62 69 74 63 6f 69 6e 63 61 73 68 3a 71 72 74 71 30 37 6a 66 68 6b 33 39 6a 36 79 64 64 39 66 63 35 79 61 33 30 6e 64 6b 6b 61 34 73 6b 75 39 63 66 36 77 73 71 39 30 } //1 bitcoincash:qrtq07jfhk39j6ydd9fc5ya30ndkka4sku9cf6wsq90
		$a_81_2 = {64 65 66 61 75 6c 74 5f 76 61 6c 75 65 5f 63 6c 69 70 70 65 72 74 31 4c 42 66 36 7a 57 64 56 59 7a 39 6f 4e 31 50 75 63 74 69 76 72 74 38 43 4c 6b 36 6b 62 75 72 41 50 } //1 default_value_clippert1LBf6zWdVYz9oN1Puctivrt8CLk6kburAP
		$a_81_3 = {4d 69 63 72 6f 73 6f 66 74 57 69 6e 64 6f 77 73 53 74 61 72 74 20 4d 65 6e 75 50 72 6f 67 72 61 6d 73 53 74 61 72 74 75 70 75 70 64 61 74 65 72 2e 6c 6e 6b } //1 MicrosoftWindowsStart MenuProgramsStartupupdater.lnk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
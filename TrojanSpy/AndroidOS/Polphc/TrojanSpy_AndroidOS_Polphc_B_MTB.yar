
rule TrojanSpy_AndroidOS_Polphc_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Polphc.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 72 65 76 65 6e 74 55 6e 69 6e 73 74 61 6c 6c } //1 PreventUninstall
		$a_00_1 = {44 69 73 61 62 6c 65 50 6c 61 79 50 72 6f 74 65 63 74 } //1 DisablePlayProtect
		$a_00_2 = {53 6d 73 41 75 74 6f 41 63 63 65 70 74 } //1 SmsAutoAccept
		$a_00_3 = {47 65 74 53 6d 73 55 70 6c 6f 61 64 } //1 GetSmsUpload
		$a_00_4 = {47 65 74 49 6e 6a 65 63 74 73 53 65 72 76 65 72 } //1 GetInjectsServer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}

rule Trojan_AndroidOS_FakeInstSms_E{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.E,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4a 6b 37 48 2e 50 77 63 44 2e 53 4c 59 66 6f 4d 64 47 } //1 Jk7H.PwcD.SLYfoMdG
		$a_00_1 = {2f 72 65 73 2f 72 61 77 2f 64 61 74 61 2e 64 62 } //1 /res/raw/data.db
		$a_00_2 = {6c 6f 61 64 53 6d 73 43 6f 75 6e 74 4d 65 74 68 6f 64 } //1 loadSmsCountMethod
		$a_02_3 = {73 65 6e 74 53 6d 73 ?? ?? 73 65 6e 74 53 6d 73 43 6f 75 6e 74 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}
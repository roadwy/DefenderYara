
rule Trojan_AndroidOS_FakeInstSms_IA{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.IA,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 65 71 74 49 43 69 53 65 6b 64 6a } //01 00  BeqtICiSekdj
		$a_00_1 = {4a 6b 37 48 2e 50 77 63 44 2e 53 4c 59 66 6f 4d 64 47 } //01 00  Jk7H.PwcD.SLYfoMdG
		$a_00_2 = {2f 72 65 73 2f 72 61 77 2f 64 61 74 61 2e 64 62 } //01 00  /res/raw/data.db
		$a_00_3 = {78 6a 79 51 6e 68 6a 73 78 6a 52 6a 79 6d 74 69 } //00 00  xjyQnhjsxjRjymti
		$a_00_4 = {5d 04 00 } //00 49 
	condition:
		any of ($a_*)
 
}
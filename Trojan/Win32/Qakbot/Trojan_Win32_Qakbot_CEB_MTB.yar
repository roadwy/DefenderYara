
rule Trojan_Win32_Qakbot_CEB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 4c 37 30 } //1 GL70
		$a_01_1 = {43 70 67 6d 65 5f 64 61 74 61 5f 69 64 65 6e 74 69 66 79 } //1 Cpgme_data_identify
		$a_01_2 = {43 70 67 6d 65 5f 64 61 74 61 5f 6e 65 77 } //1 Cpgme_data_new
		$a_01_3 = {43 70 67 6d 65 5f 64 61 74 61 5f 6e 65 77 5f 66 72 6f 6d 5f 63 62 73 } //1 Cpgme_data_new_from_cbs
		$a_01_4 = {43 70 67 6d 65 5f 64 61 74 61 5f 6e 65 77 5f 66 72 6f 6d 5f 65 73 74 72 65 61 6d } //1 Cpgme_data_new_from_estream
		$a_01_5 = {43 70 67 6d 65 5f 69 6f 5f 77 72 69 74 65 } //1 Cpgme_io_write
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule _PseudoThreat_c0001763{
	meta:
		description = "!PseudoThreat_c0001763,SIGNATURE_TYPE_MACHOHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 6e 63 2e 61 70 70 2e 63 79 6d 75 6c 61 74 65 2e 63 6f 6d } //1 cnc.app.cymulate.com
		$a_00_1 = {33 35 30 32 66 39 64 64 2d 65 32 32 65 2d 34 62 61 65 2d 38 63 30 38 2d 30 31 62 32 30 37 33 37 66 62 37 61 } //1 3502f9dd-e22e-4bae-8c08-01b20737fb7a
		$a_00_2 = {43 79 6d 75 6c 61 74 65 4c 69 6e 75 78 52 61 6e 73 6f 6d 77 61 72 65 } //1 CymulateLinuxRansomware
		$a_00_3 = {2e 43 79 6d 43 72 79 70 74 } //1 .CymCrypt
		$a_00_4 = {43 79 6d 75 6c 61 74 65 45 44 52 53 63 65 6e 61 72 69 6f 45 78 65 63 75 74 6f 72 } //1 CymulateEDRScenarioExecutor
		$a_00_5 = {2e 63 6f 6e 66 } //1 .conf
		$a_00_6 = {2e 64 6f 63 78 } //1 .docx
		$a_00_7 = {2e 70 70 74 78 } //1 .pptx
		$a_00_8 = {2e 78 6c 73 78 } //1 .xlsx
		$a_00_9 = {2e 74 62 7a 32 } //1 .tbz2
		$a_00_10 = {43 6f 6d 6d 6f 6e 43 72 79 70 74 6f 5f 61 65 73 32 35 36 } //1 CommonCrypto_aes256
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=9
 
}
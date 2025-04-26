
rule TrojanSpy_AndroidOS_Spynote_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 63 61 6c 6c 72 5f 6c 73 6e 72 5f } //1 _callr_lsnr_
		$a_01_1 = {63 6f 6e 74 61 63 74 65 64 66 77 61 6e 79 63 69 74 61 74 69 6f 6e 73 71 68 61 6e 73 64 63 65 72 74 69 66 69 65 64 61 68 6f 62 62 69 65 73 67 64 65 6c 69 63 69 6f 75 73 65 64 65 66 65 6e 64 61 6e 74 72 77 72 69 74 65 72 73 72 74 6f 64 64 6c 65 72 6c 63 61 74 68 65 64 72 61 6c 63 33 } //1 contactedfwanycitationsqhansdcertifiedahobbiesgdeliciousedefendantrwritersrtoddlerlcathedralc3
		$a_01_2 = {41 75 74 6f 5f 43 6c 69 63 6b } //1 Auto_Click
		$a_01_3 = {44 69 73 61 62 6c 65 50 6c 61 79 50 72 6f 74 65 63 74 } //1 DisablePlayProtect
		$a_01_4 = {41 63 74 69 76 53 65 6e 64 } //1 ActivSend
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
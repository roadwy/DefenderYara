
rule TrojanSpy_Win32_Derusbi_H_dha{
	meta:
		description = "TrojanSpy:Win32/Derusbi.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 43 43 5f 4d 49 53 43 } //1 PCC_MISC
		$a_01_1 = {50 43 43 5f 4d 45 44 49 41 } //1 PCC_MEDIA
		$a_01_2 = {45 41 2d 37 31 31 34 } //1 EA-7114
		$a_01_3 = {2e 62 6c 61 6e 6b 63 68 61 69 72 2e 63 6f 6d 3a 34 34 33 } //1 .blankchair.com:443
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
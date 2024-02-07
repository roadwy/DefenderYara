
rule TrojanSpy_AndroidOS_Tebak_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Tebak.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 77 6f 6f 72 69 6e 65 77 62 61 6e 6b } //01 00  com/woorinewbank
		$a_00_1 = {57 6f 6f 72 69 50 73 77 44 65 74 61 69 6c } //01 00  WooriPswDetail
		$a_00_2 = {75 70 6c 6f 61 64 42 61 6e 64 44 61 74 61 } //01 00  uploadBandData
		$a_00_3 = {57 6f 6f 72 69 43 65 72 74 41 64 61 70 74 65 72 } //01 00  WooriCertAdapter
		$a_00_4 = {73 65 6e 64 5f 62 61 6e 6b 2e 70 68 70 } //00 00  send_bank.php
	condition:
		any of ($a_*)
 
}
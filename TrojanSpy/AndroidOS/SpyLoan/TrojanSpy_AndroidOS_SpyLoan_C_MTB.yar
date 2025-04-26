
rule TrojanSpy_AndroidOS_SpyLoan_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyLoan.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 62 5f 61 63 63 6f 75 6e 74 5f 73 65 6c 65 63 74 65 64 } //1 tb_account_selected
		$a_00_1 = {72 65 71 75 65 73 74 50 65 72 6d 69 73 73 69 6f 6e 41 6e 64 55 70 6c 6f 61 64 44 65 76 69 63 65 49 6e 66 6f } //1 requestPermissionAndUploadDeviceInfo
		$a_00_2 = {43 61 73 68 53 6d 73 44 61 74 61 } //1 CashSmsData
		$a_00_3 = {43 6f 6e 66 69 72 6d 4c 6f 61 6e 41 64 61 70 74 65 72 } //1 ConfirmLoanAdapter
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
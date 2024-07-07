
rule TrojanSpy_AndroidOS_SpyLoan_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyLoan.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {67 61 74 68 65 72 5f 73 6d 73 } //1 gather_sms
		$a_00_1 = {67 61 74 68 65 72 5f 63 61 6c 6c } //1 gather_call
		$a_00_2 = {63 61 6c 6c 68 69 73 74 6f 72 79 53 74 61 74 75 73 } //1 callhistoryStatus
		$a_00_3 = {6d 6f 62 69 6c 65 49 6e 66 6f 44 61 74 61 } //1 mobileInfoData
		$a_00_4 = {46 61 6b 65 58 35 30 39 54 72 75 73 74 4d 61 6e 61 67 65 72 } //1 FakeX509TrustManager
		$a_00_5 = {63 6f 6d 2f 70 70 64 61 69 2f 6c 6f 61 6e 2f 63 6f 6d 6d 6f 6e 2f 67 61 74 68 65 72 2f 47 61 74 68 65 72 4d 67 72 } //1 com/ppdai/loan/common/gather/GatherMgr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
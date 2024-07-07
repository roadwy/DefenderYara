
rule TrojanSpy_AndroidOS_SMSSpy_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 53 4d 53 42 6c 6f 63 6b 53 74 61 74 65 } //5 bSMSBlockState
		$a_01_1 = {50 72 65 6f 64 69 63 } //1 Preodic
		$a_01_2 = {70 72 66 53 65 74 74 69 6e 67 73 } //1 prfSettings
		$a_01_3 = {6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //1 onStartCommand
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}
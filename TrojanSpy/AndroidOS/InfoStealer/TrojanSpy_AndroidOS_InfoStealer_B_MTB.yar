
rule TrojanSpy_AndroidOS_InfoStealer_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 74 68 72 65 61 64 2f 53 4d 53 52 65 63 6f 72 64 54 68 72 65 61 64 3b } //1 /thread/SMSRecordThread;
		$a_00_1 = {2f 6d 73 63 2f 6d 61 6e 61 67 65 43 4d 44 4c 69 6e 65 3b } //1 /msc/manageCMDLine;
		$a_00_2 = {66 65 74 63 68 5f 63 70 75 5f 69 6e 66 6f } //1 fetch_cpu_info
		$a_00_3 = {67 65 74 41 6c 6c 53 6d 73 73 } //1 getAllSmss
		$a_00_4 = {67 65 74 45 6d 61 69 6c 73 42 79 43 6f 6e 74 65 6e 74 49 64 } //1 getEmailsByContentId
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}

rule TrojanSpy_AndroidOS_Agent_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Agent.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 64 65 6d 6f 2f 70 72 6f 6d 65 74 68 65 75 73 2f 61 70 70 2f 48 6f 6d 65 42 52 3b } //1 Lcom/demo/prometheus/app/HomeBR;
		$a_00_1 = {24 4c 63 6f 6d 2f 64 65 6d 6f 2f 70 72 6f 6d 65 74 68 65 75 73 2f 62 65 61 6e 2f 53 6d 73 45 6e 74 69 74 79 3b } //1 $Lcom/demo/prometheus/bean/SmsEntity;
		$a_00_2 = {28 61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 61 63 74 69 6f 6e 2e 55 70 6c 6f 61 64 2e 43 61 6c 6c 2e 52 65 63 6f 72 64 } //1 (android.intent.action.Upload.Call.Record
		$a_00_3 = {75 70 6c 6f 61 64 49 6e 43 6f 6d 69 6e 67 52 65 63 6f 72 64 20 74 69 6d 65 } //1 uploadInComingRecord time
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
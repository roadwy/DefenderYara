
rule TrojanSpy_AndroidOS_GlodEagl_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GlodEagl.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 67 6f 6c 64 65 6e 2f 65 61 67 6c 65 2f } //01 00  Lcom/golden/eagle/
		$a_00_1 = {2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 67 6f 6c 64 65 6e 2e 65 61 67 6c 65 2f } //01 00  /data/data/com.golden.eagle/
		$a_00_2 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 69 6e 62 6f 78 } //01 00  content://sms/inbox
		$a_00_3 = {53 74 61 72 74 52 65 63 6f 72 64 } //01 00  StartRecord
		$a_00_4 = {63 61 6c 6c 52 65 63 6f 64 65 72 2e 61 6d 72 } //01 00  callRecoder.amr
		$a_00_5 = {67 65 74 43 61 6c 6c 48 69 73 74 6f 72 79 } //00 00  getCallHistory
		$a_00_6 = {5d 04 00 00 } //7d 36 
	condition:
		any of ($a_*)
 
}
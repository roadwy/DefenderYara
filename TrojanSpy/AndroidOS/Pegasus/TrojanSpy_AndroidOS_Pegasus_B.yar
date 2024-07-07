
rule TrojanSpy_AndroidOS_Pegasus_B{
	meta:
		description = "TrojanSpy:AndroidOS/Pegasus.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 6e 64 72 6f 69 64 43 61 6c 6c 44 69 72 65 63 74 57 61 74 63 68 65 72 20 67 65 74 43 61 6c 6c 20 } //1 AndroidCallDirectWatcher getCall 
		$a_00_1 = {53 6d 73 57 61 74 63 68 65 72 20 73 74 61 72 74 } //1 SmsWatcher start
		$a_00_2 = {52 65 63 6f 72 64 65 72 20 73 74 6f 70 52 65 63 6f 72 64 69 6e 67 20 73 74 61 72 74 } //1 Recorder stopRecording start
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
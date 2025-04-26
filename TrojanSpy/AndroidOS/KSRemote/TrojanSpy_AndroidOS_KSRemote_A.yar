
rule TrojanSpy_AndroidOS_KSRemote_A{
	meta:
		description = "TrojanSpy:AndroidOS/KSRemote.A,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {6b 73 72 65 6d 6f 74 65 2e 6a 61 72 } //2 ksremote.jar
		$a_00_1 = {45 58 50 4c 4f 49 54 5f 41 43 54 49 4f 4e } //2 EXPLOIT_ACTION
		$a_00_2 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 65 78 70 6c } //2 com.android.expl
		$a_00_3 = {63 6f 6d 70 72 65 73 73 49 6e 76 61 69 6c 64 52 65 63 6f 72 64 46 69 6c 65 } //2 compressInvaildRecordFile
		$a_00_4 = {41 6e 64 72 6f 69 64 5f 75 6e 6b 6f 77 6e } //1 Android_unkown
		$a_00_5 = {72 65 74 75 72 6e 41 75 74 6f 4a 69 7a 68 61 6e } //1 returnAutoJizhan
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}
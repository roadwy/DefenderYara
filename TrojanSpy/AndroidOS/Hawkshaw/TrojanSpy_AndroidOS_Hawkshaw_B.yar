
rule TrojanSpy_AndroidOS_Hawkshaw_B{
	meta:
		description = "TrojanSpy:AndroidOS/Hawkshaw.B,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {6d 65 2e 68 61 77 6b 73 68 61 77 } //1 me.hawkshaw
		$a_01_1 = {6d 65 2f 68 61 77 6b 73 68 61 77 2f 48 61 77 6b 73 68 61 77 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 me/hawkshaw/HawkshawMainActivity
		$a_01_2 = {6d 65 2f 68 61 77 6b 73 68 61 77 2f 74 61 73 6b 73 2f 74 65 6c 65 70 68 6f 6e 79 2f 43 61 6c 6c 52 65 63 6f 72 64 65 72 } //1 me/hawkshaw/tasks/telephony/CallRecorder
		$a_00_3 = {2f 64 65 76 69 63 65 2d 69 6e 66 6f 2f 61 75 64 69 6f } //1 /device-info/audio
		$a_01_4 = {63 6d 64 2e 67 65 74 28 22 61 72 67 31 22 29 } //1 cmd.get("arg1")
		$a_01_5 = {73 75 74 68 61 72 2d 61 63 63 65 73 73 69 62 69 6c 69 74 79 } //1 suthar-accessibility
		$a_00_6 = {2f 66 69 6c 65 73 2f 6c 6f 67 73 2e 74 78 74 } //1 /files/logs.txt
		$a_00_7 = {69 70 69 66 79 2e 6f 72 67 } //1 ipify.org
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}
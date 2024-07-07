
rule TrojanSpy_BAT_Keylog_G{
	meta:
		description = "TrojanSpy:BAT/Keylog.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 17 8d 01 00 00 01 0b 07 16 72 90 01 04 28 90 01 02 00 06 28 90 01 02 00 0a 6f 90 01 02 00 0a 28 90 01 02 00 0a 17 8d 11 00 00 01 0c 08 90 00 } //1
		$a_00_1 = {49 6e 76 6f 6b 65 00 72 61 6e 64 6f 6d } //1
		$a_01_2 = {43 6f 6e 74 72 6f 6c 4d 45 } //1 ControlME
		$a_00_3 = {7c 00 71 00 77 00 65 00 72 00 74 00 79 00 61 00 73 00 64 00 66 00 7a 00 78 00 } //1 |qwertyasdfzx
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
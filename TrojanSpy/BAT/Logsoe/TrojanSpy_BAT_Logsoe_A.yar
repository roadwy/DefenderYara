
rule TrojanSpy_BAT_Logsoe_A{
	meta:
		description = "TrojanSpy:BAT/Logsoe.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 2f 00 } //1 /keylog/
		$a_01_1 = {4b 00 65 00 79 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 76 00 } //1 Key Logger v
		$a_01_2 = {55 70 6c 6f 61 64 55 72 6c } //1 UploadUrl
		$a_01_3 = {53 65 6e 64 49 6d 61 67 65 73 } //1 SendImages
		$a_01_4 = {54 61 6b 65 53 63 72 65 65 6e 53 68 6f 74 } //1 TakeScreenShot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
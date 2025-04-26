
rule Trojan_Win32_Qbot_PBC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 73 49 6d 67 44 65 74 42 65 67 69 6e 44 65 74 65 63 74 69 6f 6e } //1 UsImgDetBeginDetection
		$a_01_1 = {55 73 49 6d 67 44 65 74 42 65 67 69 6e 44 65 74 65 63 74 69 6f 6e 42 61 6e 64 69 6e 67 } //1 UsImgDetBeginDetectionBanding
		$a_01_2 = {55 73 49 6d 67 44 65 74 42 65 67 69 6e 53 65 73 73 69 6f 6e } //1 UsImgDetBeginSession
		$a_01_3 = {55 73 49 6d 67 44 65 74 45 6e 64 44 65 74 65 63 74 69 6f 6e } //1 UsImgDetEndDetection
		$a_01_4 = {55 73 49 6d 67 44 65 74 45 6e 64 44 65 74 65 63 74 69 6f 6e 42 61 6e 64 69 6e 67 } //1 UsImgDetEndDetectionBanding
		$a_01_5 = {55 73 49 6d 67 44 65 74 45 6e 64 53 65 73 73 69 6f 6e } //1 UsImgDetEndSession
		$a_01_6 = {57 69 6e 64 } //1 Wind
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
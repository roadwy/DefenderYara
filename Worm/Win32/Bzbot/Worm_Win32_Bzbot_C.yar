
rule Worm_Win32_Bzbot_C{
	meta:
		description = "Worm:Win32/Bzbot.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_10_0 = {73 69 6d 70 6c 65 20 73 74 72 69 6e 67 20 74 6f 20 61 76 6f 69 64 20 73 74 75 70 69 64 20 61 76 20 64 65 74 65 63 74 69 6f 6e 73 } //1 simple string to avoid stupid av detections
		$a_10_1 = {49 20 61 6d 20 61 20 6e 69 67 67 65 72 } //1 I am a nigger
		$a_10_2 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtUnmapViewOfSection
		$a_10_3 = {47 65 74 46 69 6c 65 53 69 7a 65 } //1 GetFileSize
		$a_10_4 = {73 61 6e 64 62 6f 78 } //1 sandbox
	condition:
		((#a_10_0  & 1)*1+(#a_10_1  & 1)*1+(#a_10_2  & 1)*1+(#a_10_3  & 1)*1+(#a_10_4  & 1)*1) >=5
 
}
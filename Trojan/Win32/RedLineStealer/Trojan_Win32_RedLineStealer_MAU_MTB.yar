
rule Trojan_Win32_RedLineStealer_MAU_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {58 00 65 00 67 00 69 00 78 00 61 00 7a 00 65 00 } //1 Xegixaze
		$a_01_1 = {6c 00 69 00 64 00 69 00 72 00 61 00 68 00 6f 00 77 00 65 00 66 00 69 00 } //1 lidirahowefi
		$a_01_2 = {70 00 61 00 6d 00 6f 00 63 00 69 00 62 00 6f 00 74 00 6f 00 62 00 69 00 70 00 6f 00 } //1 pamocibotobipo
		$a_01_3 = {56 00 61 00 6c 00 65 00 70 00 65 00 62 00 61 00 } //1 Valepeba
		$a_01_4 = {6d 69 73 75 66 69 74 69 78 65 7a 65 68 61 } //1 misufitixezeha
		$a_01_5 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 } //1 FindFirstFile
		$a_01_6 = {42 61 63 6b 75 70 57 72 69 74 65 } //1 BackupWrite
		$a_01_7 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}

rule Trojan_Win32_Smokeloader_IA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.IA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {65 6f 76 77 77 6e 69 } //eovwwni  1
		$a_80_1 = {6c 67 72 6d 64 79 6b } //lgrmdyk  1
		$a_80_2 = {65 63 62 7a 68 72 79 } //ecbzhry  1
		$a_01_3 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //1 SystemFunction036
		$a_01_4 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //1 GetSystemInfo
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
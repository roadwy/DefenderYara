
rule Trojan_Win32_Adload_GTM_MTB{
	meta:
		description = "Trojan:Win32/Adload.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {89 4e fc 33 c0 a2 e7 ec 45 01 89 1e 89 46 08 c7 46 0c 90 01 04 89 73 10 8d 46 20 0f b7 4b 02 8d 14 08 89 53 08 03 fe 2b f9 89 7b 0c c6 03 00 89 70 fc 90 00 } //10
		$a_01_1 = {4b 69 6c 6c 54 69 6d 65 72 } //1 KillTimer
		$a_01_2 = {66 79 43 68 61 6e 67 65 4b 65 79 } //1 fyChangeKey
		$a_01_3 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //1 kLoaderLock
		$a_01_4 = {44 62 67 50 72 6f 6d 70 74 } //1 DbgPrompt
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}
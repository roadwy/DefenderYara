
rule Trojan_Win32_Sefnit_CC{
	meta:
		description = "Trojan:Win32/Sefnit.CC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 36 8b 3f 8d 4d dc 51 8d 55 98 52 6a 00 6a 00 } //2
		$a_03_1 = {6a 0a 8b ce 74 07 68 90 01 04 eb 05 68 90 01 04 e8 90 01 04 6a 0c 68 90 00 } //2
		$a_00_2 = {2e 3f 41 56 57 61 74 63 68 65 72 45 78 65 63 40 40 } //2 .?AVWatcherExec@@
		$a_01_3 = {5c 00 74 00 68 00 65 00 6d 00 65 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 \themes.dll
		$a_01_4 = {5c 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 \startup_module.dll
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
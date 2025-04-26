
rule Trojan_Win32_Mypis_CB_MTB{
	meta:
		description = "Trojan:Win32/Mypis.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {36 44 39 41 37 43 45 45 2d 30 35 34 41 2d 34 33 37 44 2d 39 39 45 46 2d 44 44 37 43 37 37 45 30 30 31 46 44 } //1 6D9A7CEE-054A-437D-99EF-DD7C77E001FD
		$a_01_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_2 = {73 68 65 6c 6c } //1 shell
		$a_01_3 = {49 6e 63 65 64 2e 42 42 43 } //1 Inced.BBC
		$a_01_4 = {57 61 68 4f 70 65 6e 43 75 72 72 65 6e 74 54 68 72 65 61 64 } //1 WahOpenCurrentThread
		$a_01_5 = {57 61 68 44 69 73 61 62 6c 65 4e 6f 6e 49 46 53 48 61 6e 64 6c 65 53 75 70 70 6f 72 74 } //1 WahDisableNonIFSHandleSupport
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
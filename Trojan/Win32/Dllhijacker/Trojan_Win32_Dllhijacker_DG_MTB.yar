
rule Trojan_Win32_Dllhijacker_DG_MTB{
	meta:
		description = "Trojan:Win32/Dllhijacker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 94 0c 64 01 00 00 88 10 41 40 3b cf 72 f1 } //1
		$a_01_1 = {35 8c 17 da 28 3b d0 75 05 } //1
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6d 73 74 72 61 63 65 72 2e 64 6c 6c } //1 c:\windows\system32\mstracer.dll
		$a_01_3 = {76 69 72 75 73 2e 77 69 6e 2e 74 72 6f 6a 61 6e 5c 6d 61 6e 74 61 6e 61 6e 69 5f 63 6f 6d 5f 68 69 6a 61 63 6b } //1 virus.win.trojan\mantanani_com_hijack
		$a_01_4 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}

rule Backdoor_Win32_Bandook_BM_MSR{
	meta:
		description = "Backdoor:Win32/Bandook.BM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 62 64 4c 61 79 65 72 44 65 73 63 72 69 70 74 6f 72 } //1 KbdLayerDescriptor
		$a_01_1 = {47 65 74 4b 65 79 53 74 61 74 65 } //1 GetKeyState
		$a_01_2 = {58 3a 5c 44 20 42 41 43 4b 55 50 20 32 39 30 33 32 30 31 34 } //1 X:\D BACKUP 29032014
		$a_01_3 = {43 69 70 68 65 72 20 6e 6f 74 20 69 6e 69 74 69 61 6c 69 7a 65 64 } //1 Cipher not initialized
		$a_01_4 = {44 43 50 62 6c 6f 63 6b 63 69 70 68 65 72 73 } //1 DCPblockciphers
		$a_01_5 = {5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c } //1 \SYSTEM\CurrentControlSet\Control\Keyboard Layouts\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
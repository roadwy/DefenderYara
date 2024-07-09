
rule Backdoor_Win32_Thoper_C{
	meta:
		description = "Backdoor:Win32/Thoper.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3a 00 53 00 6e 00 69 00 66 00 66 00 65 00 72 00 50 00 72 00 6f 00 63 00 } //1 :SnifferProc
		$a_02_1 = {5b 00 49 00 4e 00 50 00 55 00 54 00 5d 00 3a 00 [0-35] 69 00 6e 00 74 00 65 00 6c 00 2e 00 64 00 61 00 74 00 } //1
		$a_00_2 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //1 keybd_event
		$a_00_3 = {53 66 63 49 73 46 69 6c 65 50 72 6f 74 65 63 74 65 64 } //1 SfcIsFileProtected
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
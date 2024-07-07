
rule TrojanClicker_Win32_Lnkwinkap_A{
	meta:
		description = "TrojanClicker:Win32/Lnkwinkap.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 2e 00 6c 00 6e 00 6b 00 } //1 Windows Messenger.lnk
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 6c 00 6e 00 6b 00 } //1 Internet Explorer.lnk
		$a_01_2 = {4e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 6c 00 6e 00 6b 00 } //1 Notepad.lnk
		$a_01_3 = {7e 19 66 83 7c 5e fe 2e 75 11 57 } //2
		$a_01_4 = {3a 38 30 38 30 2f 73 6f 67 6f 75 63 6f 6e 66 69 67 2f } //2 :8080/sogouconfig/
		$a_01_5 = {69 23 63 25 6b 00 } //2 ⍩╣k
		$a_03_6 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 50 63 61 70 90 02 10 2e 65 78 65 00 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_03_6  & 1)*2) >=10
 
}
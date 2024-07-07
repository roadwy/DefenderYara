
rule Trojan_Win32_Avkill_E{
	meta:
		description = "Trojan:Win32/Avkill.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 72 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 5c 31 38 30 33 } //1 Software\Microsoft\Windows\CurrentVersion\Interner Settings\Zones\3\1803
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 56 73 54 73 6b 4d 67 72 2e 65 78 65 } //1 taskkill /f /im VsTskMgr.exe
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 33 36 30 53 61 66 65 5c 73 61 66 65 6d 6f 6e 5c 45 78 65 63 41 63 63 65 73 73 } //1 SOFTWARE\360Safe\safemon\ExecAccess
		$a_01_3 = {5b 48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 5c 65 78 65 66 69 6c 65 5c 44 65 66 61 75 6c 74 49 63 6f 6e 5d } //1 [HKEY_CLASSES_ROOT\exefile\DefaultIcon]
		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 52 61 76 2e 65 78 65 00 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 52 61 76 6d 6f 6e 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
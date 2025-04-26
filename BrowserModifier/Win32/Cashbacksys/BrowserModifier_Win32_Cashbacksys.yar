
rule BrowserModifier_Win32_Cashbacksys{
	meta:
		description = "BrowserModifier:Win32/Cashbacksys,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {63 61 73 68 62 61 63 6b 2d 73 79 73 62 61 72 2e 64 6c 6c } //1 cashback-sysbar.dll
		$a_01_2 = {63 61 73 68 62 61 63 6b 2d 73 79 73 5f 32 2e 64 6c 6c } //1 cashback-sys_2.dll
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 74 5c 53 65 74 74 69 6e 67 73 5c 7b 35 41 39 32 31 36 31 33 2d 33 32 33 46 2d 34 39 30 36 2d 41 30 32 36 2d 42 37 32 30 35 46 33 41 30 31 45 46 7d } //1 Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{5A921613-323F-4906-A026-B7205F3A01EF}
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_5 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
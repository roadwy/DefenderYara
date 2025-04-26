
rule Trojan_Win32_AveMaria_MT_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {43 68 65 63 6b 49 43 2e 64 6c 6c } //1 CheckIC.dll
		$a_81_1 = {52 75 6e 44 6c 67 2e 64 6c 6c } //1 RunDlg.dll
		$a_81_2 = {53 68 75 74 44 6f 77 6e 44 6c 67 2e 64 6c 6c } //1 ShutDownDlg.dll
		$a_81_3 = {49 6e 74 65 72 6e 65 74 20 57 61 6c 6b 65 72 } //1 Internet Walker
		$a_81_4 = {43 4f 4e 54 52 4f 4c 2e 45 58 45 20 6e 63 70 61 2e 63 70 6c } //1 CONTROL.EXE ncpa.cpl
		$a_81_5 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 } //1 System\CurrentControlSet\Control\Keyboard Layouts
		$a_81_6 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //1 Software\Borland\Delphi\Locales
		$a_81_7 = {45 41 63 63 65 73 73 56 69 6f 6c 61 74 69 6f 6e } //1 EAccessViolation
		$a_81_8 = {45 50 72 69 76 69 6c 65 67 65 } //1 EPrivilege
		$a_81_9 = {56 61 72 69 61 6e 74 43 68 61 6e 67 65 54 79 70 65 45 78 } //1 VariantChangeTypeEx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}

rule Backdoor_Win32_Remcos_ZJ_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.ZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 75 74 44 6f 77 6e 44 6c 67 2e 64 6c 6c } //1 ShutDownDlg.dll
		$a_01_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 \Software\Microsoft\Internet Explorer\Main
		$a_01_2 = {52 75 6e 44 6c 67 2e 64 6c 6c } //1 RunDlg.dll
		$a_01_3 = {49 6e 74 65 72 6e 65 74 20 57 61 6c 6b 65 72 } //1 Internet Walker
		$a_01_4 = {43 68 65 63 6b 49 43 2e 64 6c 6c } //1 CheckIC.dll
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
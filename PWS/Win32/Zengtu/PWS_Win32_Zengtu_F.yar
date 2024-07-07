
rule PWS_Win32_Zengtu_F{
	meta:
		description = "PWS:Win32/Zengtu.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {7a 68 65 6e 67 74 75 5f 63 6c 69 65 6e 74 } //1 zhengtu_client
		$a_00_1 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_00_3 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 CurrentVersion\Winlogon
		$a_01_4 = {53 65 6e 64 20 4f 4b } //1 Send OK
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
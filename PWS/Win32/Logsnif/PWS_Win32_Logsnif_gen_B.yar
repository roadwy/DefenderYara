
rule PWS_Win32_Logsnif_gen_B{
	meta:
		description = "PWS:Win32/Logsnif.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 6f 72 74 6f 6e 2d 6b 61 73 70 65 72 73 6b 79 2e 63 6f 6d 2f 74 72 66 2f 74 6f 6f 6c 73 } //10 http://www.norton-kaspersky.com/trf/tools
		$a_00_1 = {5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c 77 61 62 2e 65 78 65 } //1 \Outlook Express\wab.exe
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 69 72 65 63 74 33 44 58 } //1 Software\Microsoft\Direct3DX
		$a_00_3 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 57 } //1 CreateProcessW
		$a_00_4 = {4e 74 43 72 65 61 74 65 53 65 63 74 69 6f 6e } //1 NtCreateSection
		$a_00_5 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 } //1 ProgramFiles
		$a_01_6 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 46 00 69 00 6c 00 65 00 73 00 } //1 ProgramFiles
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}
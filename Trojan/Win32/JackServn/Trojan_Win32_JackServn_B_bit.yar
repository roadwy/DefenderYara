
rule Trojan_Win32_JackServn_B_bit{
	meta:
		description = "Trojan:Win32/JackServn.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 38 34 37 37 36 31 43 32 37 35 36 44 30 39 35 45 35 36 36 46 37 33 43 37 34 32 45 37 46 42 46 } //1 E847761C2756D095E566F73C742E7FBF
		$a_01_1 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 } //1 %c%c%c%c%c%c%c%c%c%c
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {6b 69 6c 6c 66 69 6c 65 2e 62 61 74 } //1 killfile.bat
		$a_01_4 = {25 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 %s\svchost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
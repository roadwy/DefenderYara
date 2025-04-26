
rule Ransom_Win32_DarkSide_MSR{
	meta:
		description = "Ransom:Win32/DarkSide!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 Elevation:Administrator
		$a_01_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 44 61 72 6b 53 69 64 65 } //1 Welcome to DarkSide
		$a_01_2 = {73 00 65 00 63 00 75 00 72 00 65 00 62 00 65 00 73 00 74 00 61 00 70 00 70 00 32 00 30 00 2e 00 63 00 6f 00 6d 00 } //1 securebestapp20.com
		$a_01_3 = {56 4d 50 72 6f 74 65 63 74 } //1 VMProtect
		$a_01_4 = {41 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All of your files are encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
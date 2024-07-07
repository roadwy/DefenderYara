
rule Backdoor_Win32_Turla_S{
	meta:
		description = "Backdoor:Win32/Turla.S,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 50 72 69 76 61 63 49 45 5c 48 69 67 68 5c 64 65 73 6b 74 6f 70 2e 69 6e 69 } //1 \Administrator\Application Data\Microsoft\Windows\PrivacIE\High\desktop.ini
		$a_01_1 = {5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 50 72 69 76 61 63 49 45 5c 48 69 67 68 5c 69 6e 64 65 78 2e 64 61 74 } //1 \Administrator\Application Data\Microsoft\Windows\PrivacIE\High\index.dat
		$a_01_2 = {39 00 37 00 72 00 79 00 75 00 68 00 66 00 30 00 32 00 33 00 } //1 97ryuhf023
		$a_01_3 = {63 00 72 00 79 00 70 00 74 00 73 00 70 00 2e 00 64 00 6c 00 6c 00 } //1 cryptsp.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
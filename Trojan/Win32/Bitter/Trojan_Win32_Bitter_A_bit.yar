
rule Trojan_Win32_Bitter_A_bit{
	meta:
		description = "Trojan:Win32/Bitter.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {8a 14 0f fe ca 88 11 41 83 ed 01 75 } //1
		$a_01_1 = {8a 14 01 fe c2 88 10 40 83 ee 01 75 } //1
		$a_01_2 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 52 75 6e } //1 reg add HKCU\Software\Microsoft\Windows\Currentversion\Run
		$a_01_3 = {62 3d 25 73 26 63 3d 25 73 26 64 3d 25 73 26 71 3d 25 64 26 72 3d 25 64 26 49 44 3d 25 64 } //1 b=%s&c=%s&d=%s&q=%d&r=%d&ID=%d
		$a_01_4 = {49 4e 46 4f 3d 00 00 00 44 57 4e 00 3c 62 72 3e 00 00 00 00 2f 66 79 66 } //1
		$a_01_5 = {2f 71 69 71 } //1 /qiq
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
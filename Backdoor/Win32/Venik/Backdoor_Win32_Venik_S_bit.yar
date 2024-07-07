
rule Backdoor_Win32_Venik_S_bit{
	meta:
		description = "Backdoor:Win32/Venik.S!bit,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 ea 90 01 01 80 f2 90 01 01 88 14 01 41 3b 90 02 04 7c 90 00 } //3
		$a_03_1 = {fe ff ff 53 c6 85 90 01 01 fe ff ff 65 c6 85 90 01 01 fe ff ff 72 c6 85 90 01 01 fe ff ff 76 c6 85 90 01 01 fe ff ff 69 c6 85 90 01 01 fe ff ff 63 c6 85 90 01 01 fe ff ff 65 c6 85 90 01 01 fe ff ff 73 c6 85 90 01 01 fe ff ff 5c c6 85 90 01 01 fe ff ff 25 c6 85 90 01 01 fe ff ff 73 88 9d 90 01 01 fe ff ff 90 00 } //3
		$a_01_2 = {3c 2f 63 6f 64 65 3e 00 3c 63 6f 64 65 3e 00 00 47 45 54 20 2f 69 6e 64 65 78 2e 70 68 70 3f 69 70 3d 25 73 } //3
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_01_4 = {59 6f 77 21 20 42 61 64 20 68 6f 73 74 20 6c 6f 6f 6b 75 70 2e 00 } //1 潙ⅷ䈠摡栠獯⁴潬歯灵.
		$a_01_5 = {48 6f 73 74 20 6e 61 6d 65 20 69 73 3a 20 25 73 0a 00 } //1
		$a_01_6 = {41 64 64 72 65 73 73 20 25 64 20 3a 20 25 73 0a 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=12
 
}
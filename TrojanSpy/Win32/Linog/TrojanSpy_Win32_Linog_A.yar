
rule TrojanSpy_Win32_Linog_A{
	meta:
		description = "TrojanSpy:Win32/Linog.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 a0 ?? ?? ?? ?? 88 85 c4 fa ff ff 6a 31 6a 00 8d 85 c5 fa ff ff 50 e8 } //2
		$a_01_1 = {5c 73 79 73 63 6f 6e 66 69 67 2e 64 61 74 00 } //1
		$a_01_2 = {2f 64 6f 77 6e 6c 6f 61 64 2f 63 64 61 74 61 2f } //1 /download/cdata/
		$a_01_3 = {6c 6f 63 61 6c 2e 66 6f 6f 2e 63 6f 6d 2e 74 78 74 } //1 local.foo.com.txt
		$a_01_4 = {2f 63 75 70 6c 6f 61 64 2e 70 68 70 00 } //1
		$a_01_5 = {2f 63 64 61 74 61 2e 70 68 70 00 } //1
		$a_01_6 = {77 6f 72 6c 64 72 65 61 64 2e 6e 65 74 31 36 2e 6e 65 74 00 } //1
		$a_01_7 = {25 73 48 6f 73 74 3a 20 25 73 } //1 %sHost: %s
		$a_01_8 = {73 73 70 6f 6f 6c 2e 76 62 73 00 } //1
		$a_01_9 = {54 00 68 00 65 00 6d 00 65 00 73 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 6c 00 6e 00 6b 00 00 00 } //1
		$a_01_10 = {73 79 73 74 65 6d 33 32 5c 6e 65 74 20 76 69 65 77 20 3e 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 61 31 2e 74 6d 70 } //1 system32\net view > c:\windows\temp\a1.tmp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=9
 
}
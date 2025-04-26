
rule Trojan_Win32_Small_AM{
	meta:
		description = "Trojan:Win32/Small.AM,SIGNATURE_TYPE_PEHSTR_EXT,25 00 1b 00 07 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 8d 45 f4 e8 ?? ?? ff ff ff 75 f4 68 ?? ?? 40 00 6a 00 68 ?? ?? 40 00 8d 45 fc ba 04 00 00 00 } //10
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_2 = {7b 33 46 44 45 42 31 37 31 2d 38 46 38 36 2d 46 46 31 31 2d 30 30 30 31 2d 36 39 42 38 44 42 35 35 33 36 38 33 7d } //10 {3FDEB171-8F86-FF11-0001-69B8DB553683}
		$a_00_3 = {73 79 73 74 65 6d 33 32 5c 73 79 73 74 65 6d 74 00 00 00 00 ff ff ff ff 04 00 00 00 2e 64 6c 6c 00 00 00 00 ff ff ff ff 04 00 00 00 64 6c 6c 31 00 } //5
		$a_00_4 = {63 3a 5c 61 61 2e 62 61 74 00 00 00 ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00 ff ff ff ff 06 00 00 00 64 65 6c 20 25 30 00 00 63 3a 5c 5c 61 61 2e 62 61 74 00 00 6f 70 65 6e 00 } //5
		$a_00_5 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_00_6 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=27
 
}
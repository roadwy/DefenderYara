
rule Trojan_Win32_RevShell_PS_MTB{
	meta:
		description = "Trojan:Win32/RevShell.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 8d c0 e5 ff ff ba ab 3c 00 00 66 89 95 f8 f7 ff ff b8 90 01 04 66 89 85 fa f7 ff ff b9 90 01 04 66 89 8d fc f7 ff ff 33 d2 66 89 95 fe f7 ff ff b8 90 01 04 66 89 85 84 f4 ff ff b9 90 01 04 66 89 8d 86 f4 ff ff ba 90 01 04 66 89 95 88 f4 ff ff 33 c0 66 89 85 8a f4 ff ff b9 90 00 } //1
		$a_01_1 = {b9 01 00 00 00 c1 e1 02 0f b6 54 0d ac 03 c2 b9 01 00 00 00 c1 e1 02 88 44 0d d4 ba 02 00 00 00 d1 e2 } //1
		$a_01_2 = {52 65 76 65 72 73 65 53 68 65 6c 6c 2e 64 6c 6c } //1 ReverseShell.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
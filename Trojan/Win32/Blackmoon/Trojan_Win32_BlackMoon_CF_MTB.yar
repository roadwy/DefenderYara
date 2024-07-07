
rule Trojan_Win32_BlackMoon_CF_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 02 03 d8 89 5d f0 6a 01 b8 2d 64 4b 00 89 45 ec 8d 45 ec 50 ff 75 f0 e8 90 02 04 8b 5d ec 85 db 74 90 00 } //5
		$a_01_1 = {62 6c 61 63 6b 69 65 76 69 72 75 73 2e 63 6f 6d 2f 73 6d 74 70 2e 74 78 74 } //1 blackievirus.com/smtp.txt
		$a_01_2 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //1 shellexecute=
		$a_01_4 = {4d 79 53 65 6c 66 2e 65 78 65 } //1 MySelf.exe
		$a_01_5 = {77 77 77 2e 62 6c 61 63 6b 69 65 76 69 72 75 73 2e 63 6f 6d 2f 74 65 78 74 2e 74 78 74 } //1 www.blackievirus.com/text.txt
		$a_01_6 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 } //1 shutdown -s -t
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=11
 
}
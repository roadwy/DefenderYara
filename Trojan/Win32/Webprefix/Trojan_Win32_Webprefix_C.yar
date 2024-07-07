
rule Trojan_Win32_Webprefix_C{
	meta:
		description = "Trojan:Win32/Webprefix.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 6c 70 72 6f 74 65 63 74 2e 65 78 65 00 } //1
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 20 50 72 6f 74 65 63 74 00 } //1
		$a_01_2 = {64 31 3d 25 64 00 00 00 26 64 32 3d 25 64 } //1
		$a_01_3 = {59 6a fd e9 75 ff ff ff 83 7d e0 00 74 06 ff 75 d8 ff } //1
		$a_01_4 = {59 33 f6 46 e9 50 fe ff ff 33 f6 e9 49 fe ff ff 55 8b ec 81 ec 10 01 00 00 53 56 57 33 db 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
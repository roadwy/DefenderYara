
rule Trojan_Win32_Voinjet_A{
	meta:
		description = "Trojan:Win32/Voinjet.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 69 6e 73 65 72 74 42 65 66 6f 72 65 28 61 64 70 72 6f 2c 20 64 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 63 68 69 6c 64 72 65 6e 2e 69 74 65 6d 28 30 29 29 } //1 document.body.insertBefore(adpro, document.body.children.item(0))
		$a_01_1 = {74 65 78 74 7c 70 61 73 73 77 6f 72 64 7c 66 69 6c 65 } //1 text|password|file
		$a_01_2 = {00 2e 65 78 65 00 73 76 63 68 6f 73 74 2e 65 78 65 00 2a 2e 65 78 65 } //1
		$a_01_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2a 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2a 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 Microsoft* Windows* Operating System
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
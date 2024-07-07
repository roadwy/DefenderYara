
rule Trojan_Win32_ClipBanker_AM_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 74 72 6f 63 65 2e 70 64 62 } //3 Release\troce.pdb
		$a_01_1 = {44 65 73 6b 74 6f 70 5c 31 } //1 Desktop\1
		$a_01_2 = {49 73 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 41 76 61 69 6c 61 62 6c 65 } //1 IsClipboardFormatAvailable
		$a_01_3 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //1 OpenClipboard
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
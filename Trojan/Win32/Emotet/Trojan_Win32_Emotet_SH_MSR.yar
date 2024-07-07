
rule Trojan_Win32_Emotet_SH_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SH!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 43 00 69 00 72 00 63 00 46 00 69 00 6c 00 65 00 44 00 65 00 6d 00 6f 00 2e 00 45 00 58 00 45 00 } //1 CCircFileDemo.EXE
		$a_01_1 = {53 68 61 72 65 56 69 6f 6c 61 74 69 6f 6e } //1 ShareViolation
		$a_01_2 = {61 62 72 61 72 5f 40 79 61 68 6f 6f 2e 63 6f 6d } //1 abrar_@yahoo.com
		$a_01_3 = {45 78 63 6c 75 64 65 55 70 64 61 74 65 } //1 ExcludeUpdate
		$a_01_4 = {63 00 72 00 65 00 61 00 74 00 65 00 20 00 65 00 6d 00 70 00 74 00 79 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //1 create empty document
		$a_01_5 = {26 00 48 00 69 00 64 00 65 00 } //1 &Hide
		$a_01_6 = {44 65 73 74 72 6f 79 57 69 6e 64 6f 77 } //1 DestroyWindow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}

rule PWS_Win32_Ldpinch_gen_C{
	meta:
		description = "PWS:Win32/Ldpinch.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6f 72 74 73 20 66 72 6f 6d 20 70 69 6e 63 68 } //3 Reports from pinch
		$a_01_1 = {49 73 4e 65 74 77 6f 72 6b 41 6c 69 76 65 00 } //1
		$a_01_2 = {4f 75 74 70 6f 73 74 20 46 69 72 65 77 61 6c 6c 20 50 72 6f } //1 Outpost Firewall Pro
		$a_01_3 = {61 74 74 72 69 62 20 2d 72 20 2d 61 20 2d 68 20 2d 73 20 25 31 } //1 attrib -r -a -h -s %1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
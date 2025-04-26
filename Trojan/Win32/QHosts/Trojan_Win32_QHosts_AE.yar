
rule Trojan_Win32_QHosts_AE{
	meta:
		description = "Trojan:Win32/QHosts.AE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_10_0 = {3d 39 31 2e 32 31 37 2e 31 35 33 2e 31 39 } //1 =91.217.153.19
		$a_10_1 = {40 65 63 68 6f 20 6f 66 66 } //1 @echo off
		$a_10_2 = {61 74 74 72 69 62 20 2d 68 20 2d 72 } //1 attrib -h -r
		$a_10_3 = {3d 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c } //1 =\system32\drivers\etc\
	condition:
		((#a_10_0  & 1)*1+(#a_10_1  & 1)*1+(#a_10_2  & 1)*1+(#a_10_3  & 1)*1) >=4
 
}

rule Trojan_Win32_VB_AGB{
	meta:
		description = "Trojan:Win32/VB.AGB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 68 6b 07 00 00 6a 31 89 75 90 01 01 89 75 90 00 } //1
		$a_02_1 = {43 00 3a 00 5c 00 43 00 61 00 6e 00 64 00 79 00 5c 00 90 02 25 5c 00 50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 31 00 2e 00 76 00 62 00 70 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
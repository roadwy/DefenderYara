
rule Trojan_Win32_Remetrac_C{
	meta:
		description = "Trojan:Win32/Remetrac.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 6c 61 79 54 69 6d 65 } //1 DelayTime
		$a_01_1 = {48 6f 73 74 73 55 72 6c 73 } //1 HostsUrls
		$a_01_2 = {68 ef cd 00 00 68 dc fe 00 00 } //2
		$a_01_3 = {05 0f 27 00 00 39 45 fc 72 bc 6a 00 } //2
		$a_03_4 = {31 ff eb 15 a0 90 01 04 38 04 1f 75 0a c6 04 1f 00 8d 5c 1f 01 eb 0c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*1) >=3
 
}
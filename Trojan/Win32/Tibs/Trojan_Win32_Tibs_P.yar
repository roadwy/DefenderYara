
rule Trojan_Win32_Tibs_P{
	meta:
		description = "Trojan:Win32/Tibs.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 01 01 00 d8 c1 c8 12 } //1
		$a_01_1 = {43 6f 70 79 42 69 6e 64 49 6e 66 6f 00 00 00 47 65 74 43 6f 6d 70 6f 6e 65 6e 74 49 44 46 72 6f 6d 43 4c 53 53 50 45 43 00 00 00 49 73 4a 49 54 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
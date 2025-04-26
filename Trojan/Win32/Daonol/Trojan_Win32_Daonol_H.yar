
rule Trojan_Win32_Daonol_H{
	meta:
		description = "Trojan:Win32/Daonol.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 38 47 45 54 20 74 04 } //1
		$a_01_1 = {63 73 65 3f 74 } //1 cse?t
		$a_01_2 = {80 a8 12 01 6a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win32_Kplo_A{
	meta:
		description = "Trojan:Win32/Kplo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {ff e0 cc cc cc cc 90 09 0e 00 cc cc cc cc 68 90 01 04 e8 90 00 } //1
		$a_02_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 90 01 04 ff 15 90 00 } //1
		$a_00_2 = {00 5c 6c 70 6b 2e 64 6c 6c 00 } //1
		$a_00_3 = {4c 70 6b 49 6e 69 74 69 61 6c 69 7a 65 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
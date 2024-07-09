
rule Trojan_Win32_Bodime_A{
	meta:
		description = "Trojan:Win32/Bodime.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 c7 44 24 ?? d5 07 66 c7 44 24 ?? 08 00 66 c7 44 24 ?? 11 00 66 c7 44 24 ?? 14 00 } //1
		$a_01_1 = {b9 00 00 04 00 b8 4b 4b 4b 4b } //1
		$a_01_2 = {77 69 6e 6e 65 74 2e 69 6d 65 } //1 winnet.ime
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
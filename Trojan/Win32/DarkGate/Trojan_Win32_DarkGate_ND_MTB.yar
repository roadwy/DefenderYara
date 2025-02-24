
rule Trojan_Win32_DarkGate_ND_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 c7 84 24 30 01 00 00 00 00 00 00 c7 84 24 34 01 00 00 07 00 00 00 66 89 84 24 20 01 00 00 83 f9 07 76 36 8b 94 24 90 00 00 00 8d 0c 4d 02 00 00 00 8b c2 81 f9 00 10 00 00 72 14 8b 50 fc 83 c1 23 2b c2 } //3
		$a_01_1 = {33 34 57 4b 53 49 2e 61 69 66 66 } //1 34WKSI.aiff
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
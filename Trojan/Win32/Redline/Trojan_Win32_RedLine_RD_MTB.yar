
rule Trojan_Win32_RedLine_RD_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ed 56 57 39 6c 24 18 76 28 0f 1f 40 00 60 0a c1 03 c3 2b d9 85 c0 61 8b 4c 24 1c 8b c5 83 e0 03 8a 04 08 8b 4c 24 14 30 04 29 45 3b 6c 24 18 72 dc 5f 5e 5d 5b c2 10 00 } //1
		$a_01_1 = {4e 00 44 00 41 00 64 00 6d 00 69 00 6e 00 2e 00 45 00 58 00 45 00 } //1 NDAdmin.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
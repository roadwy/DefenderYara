
rule Trojan_Win32_RedLine_BR_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d0 0f b6 00 c1 e0 05 32 45 f3 89 c2 0f b6 45 f3 8d 0c 02 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 8b 55 f4 8b 45 0c 01 d0 0f b6 00 89 c2 0f b6 45 f3 89 d1 29 c1 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 10 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_RedLine_BR_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e7 cd c6 45 e8 46 c6 45 e9 90 c6 45 ea ee c6 45 eb 94 c6 45 ec 63 c6 45 ed bb c6 45 ee 0a c6 45 ef c0 c6 45 f0 9a c6 45 f1 50 c6 45 f2 f1 c6 45 f3 a9 c6 45 f4 a9 c6 45 f5 b0 c6 45 f6 69 c6 45 f7 1d c6 45 f8 85 c6 45 f9 04 c6 45 fa 58 c6 45 fb 9d 6a 40 68 00 30 00 00 68 00 00 a0 00 6a 00 ff 15 } //3
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
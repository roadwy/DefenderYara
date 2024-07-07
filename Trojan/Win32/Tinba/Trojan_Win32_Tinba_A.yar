
rule Trojan_Win32_Tinba_A{
	meta:
		description = "Trojan:Win32/Tinba.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 c6 07 e9 2b c7 83 e8 05 89 47 01 eb 0e 68 00 80 00 00 } //1
		$a_01_1 = {8b 76 20 03 75 08 8b 7d 08 03 3e 83 c6 04 ba 00 00 00 00 b8 07 00 00 00 f7 e2 8b d0 0f b6 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
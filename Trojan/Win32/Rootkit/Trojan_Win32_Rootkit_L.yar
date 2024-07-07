
rule Trojan_Win32_Rootkit_L{
	meta:
		description = "Trojan:Win32/Rootkit.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 57 ff 15 90 01 04 85 c0 0f 84 90 01 04 8b ff f6 90 01 04 00 00 10 0f 90 01 03 00 00 e8 90 01 02 00 00 8b 0d 90 01 04 99 f7 f9 a1 90 01 04 3b c2 7d 08 3b c1 0f 90 00 } //1
		$a_03_1 = {68 c8 00 00 00 ff d3 8b 90 01 03 8b 0d 90 01 04 40 3b c8 89 90 01 03 7e 26 8b 90 01 03 6a 03 ff d3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
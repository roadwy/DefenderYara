
rule Trojan_Win32_Plugx_C{
	meta:
		description = "Trojan:Win32/Plugx.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {52 6a 40 03 f0 6a 10 56 ff d7 85 c0 74 35 b8 ?? ?? ?? ?? 2b c6 83 e8 05 88 46 01 8b c8 8b d0 c1 e8 18 c1 e9 08 88 46 04 c1 ea 10 8d 44 24 08 50 c6 06 e9 88 4e 02 88 56 03 8b 4c 24 0c } //1
		$a_01_1 = {8b f0 83 fe ff 74 3c 6a 00 8d 44 24 0c 50 68 00 00 10 00 57 56 ff 15 } //1
		$a_01_2 = {50 45 00 00 75 54 56 8b 71 28 57 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
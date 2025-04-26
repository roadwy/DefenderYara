
rule Trojan_Win32_Small_CI{
	meta:
		description = "Trojan:Win32/Small.CI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {be 1b 46 0d 53 89 d1 68 3e df 4e 00 81 fe 1b 46 0d 53 75 ec 03 0d 42 94 40 00 } //1
		$a_03_1 = {81 eb 99 00 00 00 81 e9 11 54 08 7a 81 c3 b5 00 00 00 8b 1b 03 15 ?? ?? 40 00 83 c9 16 b8 28 00 00 00 83 e8 20 01 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
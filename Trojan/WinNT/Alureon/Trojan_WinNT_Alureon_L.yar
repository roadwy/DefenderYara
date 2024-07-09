
rule Trojan_WinNT_Alureon_L{
	meta:
		description = "Trojan:WinNT/Alureon.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 43 46 00 00 66 3b c8 74 ?? b8 43 44 00 00 66 3b c8 75 } //1
		$a_03_1 = {a1 14 00 df ff 68 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 } //1
		$a_03_2 = {8b 43 0c 56 57 8b f8 8b 45 0c be ?? ?? ?? ?? b9 00 02 00 00 f3 a4 5f 5e 8b 0b 85 c9 74 ?? ff 73 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
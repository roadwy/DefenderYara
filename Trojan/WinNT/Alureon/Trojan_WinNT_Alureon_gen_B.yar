
rule Trojan_WinNT_Alureon_gen_B{
	meta:
		description = "Trojan:WinNT/Alureon.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 46 50 89 47 10 8b 76 28 03 f3 57 ff d6 } //1
		$a_02_1 = {68 1f 00 0f 00 8d 45 ?? 50 b8 ?? ?? ?? ?? ff d0 6a 01 6a 01 } //1
		$a_02_2 = {50 68 00 00 00 80 8d 45 ?? 50 b8 ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
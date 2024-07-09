
rule Trojan_Win32_Rimecud_gen_A{
	meta:
		description = "Trojan:Win32/Rimecud.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d2 45 ff 8a 4d 10 2a cb 32 4d ff fe c3 88 0e 3a d8 75 02 32 db fe c2 } //1
		$a_03_1 = {eb 0b 68 c8 00 00 00 ff 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? ff d3 85 c0 74 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}

rule Trojan_Win32_Dishigy_gen_A{
	meta:
		description = "Trojan:Win32/Dishigy.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 40 1c c7 80 c8 01 00 00 db 05 00 00 8b 45 f8 83 c0 34 } //1
		$a_03_1 = {69 45 f8 e7 03 00 00 50 e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? b2 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
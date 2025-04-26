
rule Trojan_Win32_Jibnuder_gen_A{
	meta:
		description = "Trojan:Win32/Jibnuder.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d ?? ?? ?? ?? 75 ed } //1
		$a_01_1 = {8d 54 24 04 cd 2e c2 1c 00 } //1
		$a_01_2 = {33 c0 8a 04 3e 8d 57 01 03 d2 33 c2 33 d2 8a d3 33 c2 88 04 3e 84 c0 75 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
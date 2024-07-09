
rule Trojan_Win32_Waprox_gen_A{
	meta:
		description = "Trojan:Win32/Waprox.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 0f 68 38 04 00 00 ff 15 ?? ?? ?? ?? 66 89 45 } //1
		$a_01_1 = {8b 43 5c 99 f7 f9 80 c2 5a 88 56 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}

rule Trojan_Win32_Waprox_gen_A{
	meta:
		description = "Trojan:Win32/Waprox.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 0f 68 38 04 00 00 ff 15 90 01 04 66 89 45 90 00 } //01 00 
		$a_01_1 = {8b 43 5c 99 f7 f9 80 c2 5a 88 56 01 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Gearclop_gen_C{
	meta:
		description = "Trojan:Win32/Gearclop.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 0f c6 06 61 00 06 c1 c0 04 46 e2 f3 } //01 00 
		$a_03_1 = {83 45 ec 03 83 45 f0 03 8d 45 e4 50 e8 90 01 04 6a 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
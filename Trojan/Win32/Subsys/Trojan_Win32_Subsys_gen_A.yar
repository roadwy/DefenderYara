
rule Trojan_Win32_Subsys_gen_A{
	meta:
		description = "Trojan:Win32/Subsys.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {d9 ee 83 ec 1c d9 34 24 8b 90 01 01 24 0c 83 c4 1c 90 00 } //01 00 
		$a_02_1 = {55 8b ec 64 a1 18 00 00 00 8b c8 64 a1 30 00 00 00 39 41 30 75 05 e8 90 01 02 ff ff 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
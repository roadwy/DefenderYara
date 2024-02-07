
rule Trojan_Win32_Rirlged_gen_A{
	meta:
		description = "Trojan:Win32/Rirlged.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 3c 3e 90 90 90 a1 75 40 81 7c 3e 08 c3 90 90 90 75 36 } //01 00 
		$a_03_1 = {74 09 81 7d 90 01 01 73 45 72 76 74 08 90 00 } //02 00 
		$a_01_2 = {c3 dc c2 eb 3a 25 73 0a d3 f2 c3 fb 3a 25 73 0a } //01 00 
		$a_01_3 = {21 2a 5f 2a 2d 3e 73 65 76 65 6e 2d 65 6c 65 76 65 6e 3c 2d 2a 5f 2a 21 } //00 00  !*_*->seven-eleven<-*_*!
	condition:
		any of ($a_*)
 
}
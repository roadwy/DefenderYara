
rule Virus_Win32_Naras_gen_A{
	meta:
		description = "Virus:Win32/Naras.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 fffffff6 ffffffff "
		
	strings :
		$a_00_0 = {50 45 5f 74 68 75 6e 6b 5f 69 6e 66 65 63 74 } //03 00 
		$a_02_1 = {e8 00 00 00 00 5b 81 eb 90 01 04 56 90 00 } //03 00 
		$a_01_2 = {c7 07 6d 73 69 6e c7 47 04 66 6d 67 72 c7 47 08 2e 65 78 65 c7 47 0c 00 00 00 00 b9 c9 bc a6 6b 8b d6 } //01 00 
		$a_01_3 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 5e 8b f0 } //01 00 
		$a_01_4 = {41 ad 03 c5 33 db 0f be 10 3a d6 74 08 c1 cb 07 03 da 40 eb f1 3b df 75 e7 } //00 00 
	condition:
		any of ($a_*)
 
}
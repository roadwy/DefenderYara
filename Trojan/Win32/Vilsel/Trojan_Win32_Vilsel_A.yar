
rule Trojan_Win32_Vilsel_A{
	meta:
		description = "Trojan:Win32/Vilsel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 bc 75 c6 45 bd 73 c6 45 be 65 c6 45 bf 72 c6 45 c0 33 c6 45 c1 32 c6 45 c2 00 } //01 00 
		$a_01_1 = {c6 45 c4 61 c6 45 c5 64 c6 45 c6 76 c6 45 c7 61 c6 45 c8 70 c6 45 c9 69 c6 45 ca 33 c6 45 cb 32 } //01 00 
		$a_01_2 = {c1 e0 07 8b 4d f8 c1 e9 19 0b c1 89 45 f8 } //00 00 
	condition:
		any of ($a_*)
 
}
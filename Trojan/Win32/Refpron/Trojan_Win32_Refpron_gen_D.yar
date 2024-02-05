
rule Trojan_Win32_Refpron_gen_D{
	meta:
		description = "Trojan:Win32/Refpron.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f8 5b 75 ed b8 61 00 00 00 8b d0 80 ea 47 33 c9 8a c8 88 54 0d 00 40 83 f8 7b 75 ed } //01 00 
		$a_03_1 = {b9 b8 0b 00 00 33 d2 b8 02 00 00 00 e8 90 01 02 ff ff 85 c0 74 53 90 00 } //01 00 
		$a_01_2 = {0f b7 d6 8d 44 10 ff 50 8b c7 8b d5 32 c2 5a 88 02 0f b7 c6 8b 14 24 0f b6 7c 02 ff 0f b7 c3 03 f8 } //00 00 
	condition:
		any of ($a_*)
 
}
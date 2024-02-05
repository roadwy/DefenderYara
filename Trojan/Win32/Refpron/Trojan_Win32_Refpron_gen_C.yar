
rule Trojan_Win32_Refpron_gen_C{
	meta:
		description = "Trojan:Win32/Refpron.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 a1 90 01 04 c6 00 01 90 02 40 66 ba 90 01 02 b8 90 01 04 e8 90 01 03 ff 8b 55 90 01 01 a1 90 01 04 e8 90 01 03 ff 8d 4d 90 01 01 66 ba 90 01 02 b8 90 01 04 e8 90 01 03 ff 8b 55 90 01 01 a1 90 01 04 e8 90 01 03 ff 8d 4d 90 01 01 66 ba 90 01 02 b8 90 01 04 e8 90 01 03 ff 8b 55 90 01 01 a1 90 01 04 e8 90 01 03 ff 8d 4d 90 01 01 66 ba 90 01 02 b8 90 01 04 e8 90 01 03 ff 90 00 } //01 00 
		$a_03_1 = {c1 eb 08 32 90 02 40 66 03 90 01 02 66 69 c0 6d ce 66 05 bf 58 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
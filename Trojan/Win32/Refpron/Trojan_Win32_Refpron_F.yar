
rule Trojan_Win32_Refpron_F{
	meta:
		description = "Trojan:Win32/Refpron.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d ba db 00 8b 45 f0 50 a1 90 01 04 8b 00 ff d0 89 45 ec 81 7d ec 02 01 00 00 90 13 c6 45 fb 01 33 c0 90 00 } //01 00 
		$a_03_1 = {c7 45 e4 6d ce 00 00 90 02 20 66 05 bf 58 90 00 } //01 00 
		$a_03_2 = {b8 32 00 00 00 e8 90 01 04 83 c0 0a 89 45 90 01 01 69 45 90 01 01 e8 03 00 00 e8 90 00 } //01 00 
		$a_01_3 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Sebiomac_gen_B{
	meta:
		description = "Trojan:Win32/Sebiomac.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 31 c6 45 e9 c0 c6 45 ea c3 c7 45 e4 00 00 00 00 89 04 24 } //01 00 
		$a_03_1 = {31 db 89 9d 90 01 04 c6 85 90 01 04 c0 c6 85 90 01 04 c3 90 09 07 00 c6 85 90 01 04 31 90 00 } //02 00 
		$a_01_2 = {c7 04 30 5c 6c 73 61 ba 73 73 2e 65 31 c9 89 54 30 04 66 c7 44 30 08 78 65 c6 44 30 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}
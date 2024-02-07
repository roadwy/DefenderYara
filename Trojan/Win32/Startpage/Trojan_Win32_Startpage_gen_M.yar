
rule Trojan_Win32_Startpage_gen_M{
	meta:
		description = "Trojan:Win32/Startpage.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 80 41 42 00 50 8b cf e8 5d 54 01 00 8b 8e dc 00 00 00 68 7c 41 42 00 e8 87 5e 01 00 8b 8e dc 00 00 00 68 78 41 42 00 e8 77 5e 01 00 8b 8e dc 00 00 00 68 78 41 42 00 e8 67 5e 01 00 8b 8e dc 00 00 00 } //02 00 
		$a_01_1 = {54 68 65 57 6f 72 6c 64 2e 69 6e 69 } //02 00  TheWorld.ini
		$a_01_2 = {72 72 35 35 2e 63 6f 6d 2f 3f 7a 7a } //02 00  rr55.com/?zz
		$a_01_3 = {67 6f 32 30 30 30 2e 63 6e 2f 3f 7a 7a } //00 00  go2000.cn/?zz
	condition:
		any of ($a_*)
 
}
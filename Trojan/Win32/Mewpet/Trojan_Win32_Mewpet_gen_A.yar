
rule Trojan_Win32_Mewpet_gen_A{
	meta:
		description = "Trojan:Win32/Mewpet.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 18 ff 53 34 a1 90 01 04 8b 00 8b 10 ff 52 3c 33 c0 5a 59 59 90 00 } //01 00 
		$a_03_1 = {70 74 6d 70 32 90 03 01 01 64 68 5f 73 76 63 90 00 } //01 00 
		$a_01_2 = {3f 00 63 00 70 00 75 00 3d 00 25 00 35 00 2e 00 32 00 66 00 26 00 6d 00 65 00 6d 00 3d 00 25 00 35 00 2e 00 32 00 66 00 26 00 70 00 3d 00 25 00 64 00 } //00 00  ?cpu=%5.2f&mem=%5.2f&p=%d
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Trickster_A{
	meta:
		description = "Trojan:Win32/Trickster.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 73 04 8b 13 83 c3 08 03 96 00 00 40 00 8d 86 00 00 40 00 89 55 cc e8 8f fd ff ff 8b 45 cc 81 fb 20 95 41 00 89 86 00 00 40 00 72 d3 } //01 00 
		$a_00_1 = {8b 45 f4 8d 50 0c 8b 45 0c 2b 45 f4 8d 48 ff 8b 45 08 01 c8 0f b6 00 88 82 80 81 41 00 83 45 f4 01 8b 45 f4 3b 45 0c 7c d7 } //01 00 
		$a_01_2 = {31 2e 48 4b 65 } //00 00  1.HKe
	condition:
		any of ($a_*)
 
}
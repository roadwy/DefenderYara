
rule Trojan_Win32_Gatak_DX_dha{
	meta:
		description = "Trojan:Win32/Gatak.DX!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 89 45 fc 8b 45 fc 8b 40 0c 8b 40 0c 53 c6 45 ec 6e c6 45 ed 74 c6 45 ee 64 c6 45 ef 6c c6 45 f0 6c c6 45 f1 2e c6 45 f2 64 c6 45 f3 6c c6 45 f4 6c c6 45 f5 00 56 66 83 78 2c 12 75 90 01 01 8b 48 30 33 f6 8a 11 8a da 80 eb 41 80 fb 19 77 90 01 01 80 c2 20 38 54 35 ec 75 90 01 01 46 41 41 83 fe 09 72 90 01 01 8b 40 18 90 00 } //00 00 
		$a_00_1 = {5d 04 00 00 b5 } //3c 03 
	condition:
		any of ($a_*)
 
}
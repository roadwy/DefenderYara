
rule Trojan_Win32_Shetwirl_A{
	meta:
		description = "Trojan:Win32/Shetwirl.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {be 00 02 00 00 56 8d 85 90 01 02 ff ff 50 ff 75 08 ff 15 90 01 04 85 c0 0f 84 28 02 00 00 b8 55 aa 00 00 66 39 85 90 01 02 ff ff 90 00 } //02 00 
		$a_03_1 = {8b 45 08 8d 0c 02 8b 01 8b f0 c1 e6 19 c1 e8 07 03 f0 81 f6 90 01 04 83 c2 04 3b 55 0c 89 31 7c de 90 00 } //01 00 
		$a_00_2 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 25 00 64 00 } //00 00  \\.\PhysicalDrive%d
	condition:
		any of ($a_*)
 
}
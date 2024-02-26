
rule Trojan_Win32_Vidar_NVV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 f6 81 3d a0 2c 45 00 90 01 04 57 75 43 56 e8 fc 03 00 00 59 56 e8 de 05 00 00 59 56 56 e8 f6 08 00 00 8b c4 89 30 89 70 04 e8 ff f9 ff ff 90 00 } //01 00 
		$a_01_1 = {70 6c 61 63 65 6d 65 6e 74 20 64 65 6c 65 74 65 5b 5d 20 63 6c 6f 73 75 72 65 } //00 00  placement delete[] closure
	condition:
		any of ($a_*)
 
}
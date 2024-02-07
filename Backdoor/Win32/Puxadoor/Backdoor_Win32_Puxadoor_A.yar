
rule Backdoor_Win32_Puxadoor_A{
	meta:
		description = "Backdoor:Win32/Puxadoor.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 75 00 78 00 61 00 73 00 69 00 73 00 74 00 65 00 6d 00 61 00 } //01 00  puxasistema
		$a_01_1 = {70 75 78 61 64 6f 72 } //02 00  puxador
		$a_01_2 = {56 65 72 69 66 69 63 61 72 41 70 6c 69 63 61 74 69 76 6f } //02 00  VerificarAplicativo
		$a_01_3 = {8b 75 10 8d 45 dc 8b 16 52 50 ff d7 8b 5d 0c } //02 00 
		$a_03_4 = {be 08 00 00 00 83 c4 0c 8d 95 54 fd ff ff 8d 8d 84 fd ff ff c7 85 5c fd ff ff 90 01 03 00 89 b5 54 fd ff ff ff 15 90 01 03 00 8d 85 84 fd ff ff 8d 8d 74 fd ff ff 50 51 ff 15 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Dofoil_AG_bit{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AG!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 90 01 01 40 89 45 90 01 01 8b 85 90 01 01 ff ff ff 8b 84 85 90 01 02 ff ff 8b 4d 90 01 01 0f be 04 08 0f b6 4d 90 01 01 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 8b 45 90 01 01 03 45 90 01 01 0f be 00 85 c0 75 02 eb 02 eb c6 90 00 } //01 00 
		$a_01_1 = {63 6c 69 65 6e 74 5f 69 64 3d 25 2e 38 78 26 63 6f 6e 6e 65 63 74 65 64 3d 25 64 26 73 65 72 76 65 72 5f 70 6f 72 74 3d 25 64 26 64 65 62 75 67 3d 25 64 26 6f 73 3d 25 64 2e 25 64 2e 25 30 34 64 26 64 67 74 3d 25 64 } //01 00  client_id=%.8x&connected=%d&server_port=%d&debug=%d&os=%d.%d.%04d&dgt=%d
		$a_01_2 = {2f 73 69 6e 67 6c 65 2e 70 68 70 3f 63 3d 25 73 } //01 00  /single.php?c=%s
		$a_01_3 = {68 65 79 66 67 36 34 35 66 64 68 77 69 } //01 00  heyfg645fdhwi
		$a_01_4 = {5c 00 6c 00 6f 00 63 00 6b 00 2e 00 64 00 61 00 74 00 } //00 00  \lock.dat
	condition:
		any of ($a_*)
 
}
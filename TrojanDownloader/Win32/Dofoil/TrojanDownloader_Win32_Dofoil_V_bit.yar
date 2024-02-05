
rule TrojanDownloader_Win32_Dofoil_V_bit{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.V!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 ca 8a 0c 01 8b 35 90 01 03 00 83 c6 03 0f af 75 90 01 01 03 75 90 01 01 88 0c 02 83 c0 01 3b 45 90 01 01 89 75 90 01 01 7c ce 90 00 } //02 00 
		$a_03_1 = {8b c6 2b c1 83 e8 04 0f af c7 8b 5d 90 01 01 8b 7d 90 01 01 83 c2 01 8d 48 03 0f af ca 8b 55 90 01 01 0f af ce 2b d9 8a 0c 17 32 cb 85 f6 74 05 88 0c 17 eb 03 88 14 17 90 00 } //01 00 
		$a_03_2 = {5f 5e 5b 8b e5 5d c2 10 00 90 09 05 00 8b 6d 90 01 01 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
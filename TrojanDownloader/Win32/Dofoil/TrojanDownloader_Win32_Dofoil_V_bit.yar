
rule TrojanDownloader_Win32_Dofoil_V_bit{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.V!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 ca 8a 0c 01 8b 35 ?? ?? ?? 00 83 c6 03 0f af 75 ?? 03 75 ?? 88 0c 02 83 c0 01 3b 45 ?? 89 75 ?? 7c ce } //2
		$a_03_1 = {8b c6 2b c1 83 e8 04 0f af c7 8b 5d ?? 8b 7d ?? 83 c2 01 8d 48 03 0f af ca 8b 55 ?? 0f af ce 2b d9 8a 0c 17 32 cb 85 f6 74 05 88 0c 17 eb 03 88 14 17 } //2
		$a_03_2 = {5f 5e 5b 8b e5 5d c2 10 00 90 09 05 00 8b 6d ?? ff d5 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}
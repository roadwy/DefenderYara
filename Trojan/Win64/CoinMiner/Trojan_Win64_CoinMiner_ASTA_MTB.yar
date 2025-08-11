
rule Trojan_Win64_CoinMiner_ASTA_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.ASTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {4d 8b c5 48 83 3d ?? ?? ?? ?? 0f 4c 0f 47 05 ?? ?? ?? ?? 33 d2 48 8b c1 48 f7 35 ?? ?? ?? ?? 49 03 d0 4c 8d 44 24 50 48 83 7c 24 68 0f 4c 0f 47 44 24 50 0f b6 02 41 32 04 09 41 88 04 08 48 ff c1 49 3b ca 72 } //5
		$a_01_1 = {5c 53 61 70 70 68 69 72 65 5f 4d 69 6e 65 72 5f 53 6f 75 72 63 65 5c 53 61 70 70 68 69 72 65 43 6c 69 65 6e 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 61 70 70 68 69 72 65 43 6c 69 65 6e 74 2e 70 64 62 } //1 \Sapphire_Miner_Source\SapphireClient\x64\Release\SapphireClient.pdb
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 27 63 6d 64 2e 65 78 65 27 3b 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 43 3a 5c 27 22 } //1 powershell -Command "Add-MpPreference -ExclusionProcess 'cmd.exe'; Add-MpPreference -ExclusionPath 'C:\'"
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
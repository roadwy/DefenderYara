
rule Trojan_Win64_PSWStealer_GNN_MTB{
	meta:
		description = "Trojan:Win64/PSWStealer.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {48 8b 05 82 d6 07 00 48 33 c4 48 89 84 24 ?? ?? ?? ?? 45 8b d9 45 0f b6 d0 48 8b 01 48 83 7a 10 00 75 2b 44 0f b6 8c 24 ?? ?? ?? ?? 45 8b c3 41 0f b6 d2 ff 50 60 48 8b 8c 24 ?? ?? ?? ?? 48 33 cc e8 ?? ?? ?? ?? 48 81 c4 ?? ?? ?? ?? c3 } //10
		$a_01_1 = {68 68 69 75 65 77 33 33 2e 63 6f 6d } //1 hhiuew33.com
		$a_01_2 = {66 6a 34 67 68 67 61 32 33 5f 66 73 61 2e 74 78 74 } //1 fj4ghga23_fsa.txt
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
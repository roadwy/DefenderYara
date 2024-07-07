
rule Trojan_WinNT_Fetrog_B{
	meta:
		description = "Trojan:WinNT/Fetrog.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 65 72 66 6e 77 2e 70 64 62 } //1 perfnw.pdb
		$a_01_1 = {0f b6 42 08 41 0f b7 c9 66 41 83 c1 02 42 30 04 01 0f b6 42 08 42 30 44 01 01 66 44 3b 4a 20 72 df } //2
		$a_03_2 = {66 41 89 43 04 44 0f b7 5c 24 90 01 01 44 0f b7 6c 24 90 01 01 66 41 81 f3 aa 55 66 41 81 f5 55 aa 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=4
 
}
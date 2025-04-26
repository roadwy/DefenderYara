
rule Trojan_Win32_Brosin_A_dha{
	meta:
		description = "Trojan:Win32/Brosin.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6d 53 70 65 63 00 20 3e 3e 20 4e 55 4c 00 2f 63 20 64 65 6c 20 00 } //2 潃卭数c㸠‾啎L振搠汥 
		$a_01_1 = {45 42 45 54 46 59 42 59 41 47 4a 4b } //1 EBETFYBYAGJK
		$a_01_2 = {45 41 42 47 46 48 44 43 45 51 47 47 44 43 44 54 43 54 44 56 46 4a 49 47 48 48 42 45 42 43 47 42 4a 55 } //1 EABGFHDCEQGGDCDTCTDVFJIGHHBEBCGBJU
		$a_01_3 = {55 6e 6b 6e 6f 77 20 43 50 55 } //1 Unknow CPU
		$a_03_4 = {8a 02 b1 1a f6 e9 8a 4a 01 8b fd 02 c1 83 c9 ff 04 25 83 c2 02 88 44 34 ?? 33 c0 46 } //2
		$a_01_5 = {8b fd 8d 0c 40 c1 e1 04 2b c8 8d 0c 49 8d 0c 89 8d 0c c9 8d 04 48 83 c9 ff 2b d8 33 c0 42 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2+(#a_01_5  & 1)*2) >=3
 
}
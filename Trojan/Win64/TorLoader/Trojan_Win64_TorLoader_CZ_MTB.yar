
rule Trojan_Win64_TorLoader_CZ_MTB{
	meta:
		description = "Trojan:Win64/TorLoader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 54 54 4f 74 74 63 66 77 4f 46 46 77 4f 46 32 50 4b } //2 OTTOttcfwOFFwOF2PK
		$a_01_1 = {5a 72 32 4a 46 74 52 51 4e 58 33 42 43 5a 38 59 74 78 52 45 39 68 4e 4a 59 43 38 4a 36 49 31 4d 56 62 4d 67 36 6f 77 55 70 31 38 } //2 Zr2JFtRQNX3BCZ8YtxRE9hNJYC8J6I1MVbMg6owUp18
		$a_01_2 = {47 79 54 34 6e 4b 2f 59 44 48 53 71 61 31 63 34 37 35 33 6f 75 59 43 44 61 6a 4f 59 4b 54 6a 61 39 58 62 2f 4f 48 74 67 76 53 77 } //2 GyT4nK/YDHSqa1c4753ouYCDajOYKTja9Xb/OHtgvSw
		$a_01_3 = {4e 6a 52 46 55 52 33 7a 73 31 4a 50 55 43 67 61 43 58 53 68 33 53 57 36 32 75 41 4b 54 31 6d 53 42 4d } //1 NjRFUR3zs1JPUCgaCXSh3SW62uAKT1mSBM
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
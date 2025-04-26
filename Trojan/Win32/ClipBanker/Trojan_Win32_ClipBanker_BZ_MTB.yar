
rule Trojan_Win32_ClipBanker_BZ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 4d d0 e8 ?? ?? fc ff 83 c0 01 50 8b f4 8b 45 c4 50 ff 15 ?? ?? 71 00 3b f4 e8 ?? ?? fc ff 50 e8 ?? ?? fc ff 83 c4 0c 8b f4 8b 45 c4 50 ff 15 ?? ?? 71 00 3b f4 e8 ?? ?? fc ff 8b f4 8b 45 c4 50 6a 01 ff 15 ?? ?? 71 00 3b f4 e8 ?? ?? fc ff 8b f4 ff 15 ?? ?? 71 00 3b f4 } //2
		$a_01_1 = {28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 33 39 7d 24 } //1 (bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$
		$a_01_2 = {30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 24 } //1 0x[a-fA-F0-9]{40}$
		$a_01_3 = {44 7b 31 7d 5b 35 2d 39 41 2d 48 4a 2d 4e 50 2d 55 5d 7b 31 7d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 33 32 7d 24 } //1 D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
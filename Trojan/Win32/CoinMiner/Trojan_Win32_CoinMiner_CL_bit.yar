
rule Trojan_Win32_CoinMiner_CL_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.CL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {39 7d 0c 7e 17 56 8b 45 08 8d 34 07 8b c3 e8 ?? ?? ?? ff 30 06 47 3b 7d 0c 7c eb } //1
		$a_03_1 = {81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 88 ?? ?? ?? 00 8a 0c 01 30 0a 8b 90 90 ?? ?? ?? 00 8a 14 02 8b 88 ?? ?? ?? 00 30 14 01 8b 90 90 ?? ?? ?? 00 8a 14 02 8b 88 ?? ?? ?? 00 30 14 01 8b 88 ?? ?? ?? 00 8b 90 90 ?? ?? ?? 00 0f b6 0c 01 0f b6 14 02 03 ca 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 04 01 } //1
		$a_01_2 = {00 6d 69 6e 65 72 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
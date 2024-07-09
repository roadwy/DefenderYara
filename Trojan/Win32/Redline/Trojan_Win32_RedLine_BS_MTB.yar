
rule Trojan_Win32_RedLine_BS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a eb } //1
		$a_00_1 = {50 4f 56 34 68 70 33 48 79 37 74 46 31 72 32 6d } //1 POV4hp3Hy7tF1r2m
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_RedLine_BS_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 85 f4 fb ff ff 0f b6 00 8b 8d e4 f7 ff ff 33 84 8d f8 fb ff ff 8b 8d f0 fb ff ff 03 8d f4 fb ff ff 88 01 e9 } //3
		$a_01_1 = {45 78 6f 64 75 73 20 57 65 62 33 20 57 61 6c 6c 65 74 } //1 Exodus Web3 Wallet
		$a_01_2 = {4b 65 65 50 61 73 73 20 54 75 73 6b } //1 KeePass Tusk
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_Win32_RedLine_BS_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 d0 c1 e0 05 32 45 ef 89 c3 0f b6 4d ef 8b 55 f0 8b 45 0c 01 d0 8d 14 0b 88 10 8b 55 f0 8b 45 0c 01 d0 0f b6 10 0f b6 5d ef 8b 4d f0 8b 45 0c 01 c8 29 da 88 10 83 45 f0 01 8b 45 f0 3b 45 10 72 } //1
		$a_01_1 = {36 00 47 00 38 00 4c 00 32 00 70 00 6d 00 33 00 54 00 59 00 5c 00 55 00 4d 00 6b 00 45 00 68 00 59 00 71 00 33 00 } //1 6G8L2pm3TY\UMkEhYq3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
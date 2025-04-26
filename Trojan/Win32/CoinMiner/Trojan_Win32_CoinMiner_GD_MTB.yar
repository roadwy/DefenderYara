
rule Trojan_Win32_CoinMiner_GD_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_80_0 = {50 68 6f 65 6e 69 78 4d 69 6e 65 72 } //PhoenixMiner  1
		$a_80_1 = {4b 72 79 70 74 65 78 } //Kryptex  1
		$a_80_2 = {6e 61 6e 6f 6d 69 6e 65 72 } //nanominer  1
		$a_80_3 = {70 72 6f 6d 65 74 68 65 72 69 6f 6e } //prometherion  1
		$a_80_4 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  1
		$a_80_5 = {45 74 68 44 63 72 4d 69 6e 65 72 36 34 } //EthDcrMiner64  1
		$a_80_6 = {74 2d 72 65 78 } //t-rex  1
		$a_80_7 = {78 6d 72 69 67 2d 63 75 64 61 2e 64 6c 6c } //xmrig-cuda.dll  1
		$a_80_8 = {63 6f 6e 66 69 67 2e 74 78 74 } //config.txt  1
		$a_80_9 = {73 74 63 2e 62 61 74 } //stc.bat  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=8
 
}
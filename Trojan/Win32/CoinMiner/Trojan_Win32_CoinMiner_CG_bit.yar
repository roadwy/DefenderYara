
rule Trojan_Win32_CoinMiner_CG_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.CG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 65 72 2e 53 74 61 72 74 } //2 miner.Start
		$a_01_1 = {2f 4d 69 63 72 6f 73 6f 66 74 2f 4e 65 74 77 6f 72 6b 2f 43 6f 6e 6e 65 63 74 69 6f 6e 73 2f 68 6f 73 74 64 6c 2e 65 78 65 } //1 /Microsoft/Network/Connections/hostdl.exe
		$a_01_2 = {64 65 66 65 6e 64 65 72 2e 4b 69 6c 6c 28 29 } //1 defender.Kill()
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win64_CoinMiner_GVA_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 45 6e 73 75 72 65 58 6d 72 69 67 } //1 main.EnsureXmrig
		$a_01_1 = {6d 61 69 6e 2e 58 6d 72 69 67 50 61 74 68 } //1 main.XmrigPath
		$a_01_2 = {6d 61 69 6e 2e 65 78 74 72 61 63 74 5a 69 70 41 6e 64 53 61 76 65 } //1 main.extractZipAndSave
		$a_01_3 = {6d 61 69 6e 2e 6b 69 6c 6c 45 78 69 73 74 69 6e 67 4d 69 6e 65 72 73 } //1 main.killExistingMiners
		$a_01_4 = {6d 61 69 6e 2e 53 74 61 72 74 4d 69 6e 65 72 } //1 main.StartMiner
		$a_01_5 = {2f 78 6d 72 69 67 } //1 /xmrig
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
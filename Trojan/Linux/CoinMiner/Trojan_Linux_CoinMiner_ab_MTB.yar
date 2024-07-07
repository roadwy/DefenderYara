
rule Trojan_Linux_CoinMiner_ab_MTB{
	meta:
		description = "Trojan:Linux/CoinMiner.ab!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 68 6d 6f 64 20 37 37 37 20 25 73 3b 25 73 20 25 73 20 2d 6c 20 2f 74 6d 70 2f 25 73 2e 74 78 74 } //1 chmod 777 %s;%s %s -l /tmp/%s.txt
		$a_00_1 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //1 stratum+tcp://
		$a_00_2 = {6d 69 6e 65 72 } //1 miner
		$a_00_3 = {57 65 6c 63 6f 6d 65 20 74 6f 20 53 61 74 61 6e 20 44 44 6f 53 21 } //1 Welcome to Satan DDoS!
		$a_00_4 = {4d 6f 64 65 20 6f 66 20 69 6e 66 65 63 74 69 6f 6e 20 46 54 50 2c 49 50 43 2c 53 4d 42 2c 57 4d 49 2c 4d 53 53 51 4c 2c 45 74 65 72 6e 61 6c 42 6c 75 65 } //1 Mode of infection FTP,IPC,SMB,WMI,MSSQL,EternalBlue
		$a_00_5 = {42 6c 61 63 6b 53 71 75 69 64 4d 69 6e 69 6e 67 2c 53 70 72 65 61 64 4d 69 6e 65 72 } //1 BlackSquidMining,SpreadMiner
		$a_00_6 = {70 6f 73 74 61 74 74 61 63 6b } //1 postattack
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}
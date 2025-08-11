
rule TrojanSpy_AndroidOS_RewardSteal_AD_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 65 72 45 78 65 63 75 74 61 62 6c 65 44 6f 77 6e 6c 6f 61 64 } //1 MinerExecutableDownload
		$a_01_1 = {4b 45 59 5f 45 58 45 43 55 54 41 42 4c 45 5f 44 4f 57 4e 4c 4f 41 44 45 44 } //1 KEY_EXECUTABLE_DOWNLOADED
		$a_01_2 = {2f 65 78 61 6d 70 6c 65 2f 66 63 6d 65 78 70 72 2f 6d 69 6e 65 72 } //1 /example/fcmexpr/miner
		$a_01_3 = {4d 69 6e 69 6e 67 54 72 61 63 6b 65 72 } //1 MiningTracker
		$a_01_4 = {2f 65 78 61 6d 70 6c 65 2f 66 63 6d 65 78 70 72 2f 6b 65 65 70 61 6c 69 76 65 2f 4b 65 65 70 41 6c 69 76 65 52 65 63 65 69 76 65 72 } //1 /example/fcmexpr/keepalive/KeepAliveReceiver
		$a_01_5 = {75 61 73 65 63 75 72 69 74 79 2e 6f 72 67 2f } //1 uasecurity.org/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
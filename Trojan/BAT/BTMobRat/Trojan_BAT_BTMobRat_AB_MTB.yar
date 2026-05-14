
rule Trojan_BAT_BTMobRat_AB_MTB{
	meta:
		description = "Trojan:BAT/BTMobRat.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 63 6f 69 6e 5f 6d 6f 6e 65 72 6f 31 } //1 get_coin_monero1
		$a_81_1 = {42 54 4d 4f 42 2e 43 61 6d 65 72 61 4d 6f 6e 69 74 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //1 BTMOB.CameraMonitor.resources
		$a_81_2 = {4f 66 66 6c 69 6e 65 20 6b 65 79 6c 6f 67 67 65 72 } //1 Offline keylogger
		$a_81_3 = {42 54 4d 4f 42 2e 4c 69 76 65 4b 65 79 6c 6f 67 67 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 BTMOB.LiveKeylogger.resources
		$a_81_4 = {42 54 4d 6f 62 2e 65 78 65 } //1 BTMob.exe
		$a_81_5 = {6d 69 6e 65 72 } //1 miner
		$a_81_6 = {70 61 79 6c 6f 61 64 } //1 payload
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}

rule Trojan_Win64_CoinMiner_LMU_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.LMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 08 00 00 "
		
	strings :
		$a_81_0 = {52 65 73 75 6d 69 6e 67 2c 20 50 49 44 } //1 Resuming, PID
		$a_81_1 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 58 4d 52 69 67 20 66 72 6f 6d 20 72 65 73 6f 75 72 63 65 73 3a } //2 [-] Failed to load XMRig from resources:
		$a_81_2 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 47 4d 69 6e 65 72 20 66 72 6f 6d 20 72 65 73 6f 75 72 63 65 73 3a } //3 [-] Failed to load GMiner from resources:
		$a_81_3 = {5b 2b 5d 20 43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 42 6e 65 74 20 54 6f 72 20 53 65 72 76 69 63 65 20 28 39 30 35 30 29 } //4 [+] Connected to Bnet Tor Service (9050)
		$a_81_4 = {5b 2a 5d 20 43 50 55 20 6d 69 6e 69 6e 67 20 64 69 73 61 62 6c 65 64 2c 20 73 6b 69 70 70 69 6e 67 20 58 4d 52 69 67 20 69 6e 6a 65 63 74 69 6f 6e } //5 [*] CPU mining disabled, skipping XMRig injection
		$a_81_5 = {5b 49 44 4c 45 5f 43 48 45 43 4b 5d 20 49 64 6c 65 20 74 69 6d 65 3a } //6 [IDLE_CHECK] Idle time:
		$a_81_6 = {5b 2a 5d 20 43 68 65 63 6b 69 6e 67 20 69 66 20 64 65 76 69 63 65 20 69 73 20 69 64 6c 65 20 28 74 68 72 65 73 68 6f 6c 64 3a } //7 [*] Checking if device is idle (threshold:
		$a_81_7 = {5d 20 43 50 55 20 6d 69 6e 65 72 20 43 52 41 53 48 45 44 2c 20 72 65 73 74 61 72 74 69 6e 67 2e 2e 2e } //8 ] CPU miner CRASHED, restarting...
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8) >=35
 
}
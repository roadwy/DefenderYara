
rule Trojan_Win64_SpyAgent_CX_MTB{
	meta:
		description = "Trojan:Win64/SpyAgent.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 61 70 74 75 72 65 41 6e 64 50 72 6f 63 65 73 73 53 63 72 65 65 6e 73 68 6f 74 } //5 captureAndProcessScreenshot
		$a_01_1 = {62 65 61 63 6f 6e 4c 6f 6f 70 } //5 beaconLoop
		$a_01_2 = {64 65 74 65 63 74 41 56 50 72 6f 64 75 63 74 73 } //5 detectAVProducts
		$a_01_3 = {65 78 65 63 75 74 65 50 45 35 45 78 70 6c 6f 69 74 } //5 executePE5Exploit
		$a_01_4 = {54 65 6c 65 67 72 61 6d 43 32 48 61 6e 64 6c 65 72 } //5 TelegramC2Handler
		$a_01_5 = {68 61 6e 64 6c 65 45 78 66 69 6c 74 72 61 74 65 } //5 handleExfiltrate
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=30
 
}
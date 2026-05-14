
rule Trojan_Win64_BroPass_AH_MTB{
	meta:
		description = "Trojan:Win64/BroPass.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 68 61 74 73 41 70 70 20 53 65 73 73 69 6f 6e 20 48 69 6a 61 63 6b 20 2d 20 49 6e 73 74 72 75 63 74 69 6f 6e 73 } //10 WhatsApp Session Hijack - Instructions
		$a_01_1 = {5b 2b 5d 20 43 6c 69 70 62 6f 61 72 64 20 64 61 74 61 20 73 74 6f 6c 65 6e 20 28 55 6e 69 63 6f 64 65 2c 20 25 64 20 63 68 61 72 73 29 } //20 [+] Clipboard data stolen (Unicode, %d chars)
		$a_01_2 = {7b 22 73 65 63 72 65 74 22 3a 22 25 73 22 2c 22 61 63 74 69 6f 6e 22 3a 22 25 73 22 2c 22 66 69 6c 65 6e 61 6d 65 22 3a 22 25 73 22 2c 22 70 72 6f 67 72 65 73 73 22 3a 25 6c 75 2c 22 62 79 74 65 73 5f 73 65 6e 74 22 3a 25 6c 75 2c 22 74 6f 74 61 6c 5f 62 79 74 65 73 22 3a 25 6c 75 2c 22 63 75 73 74 6f 6d 65 72 5f 69 64 22 3a 22 25 73 22 7d } //30 {"secret":"%s","action":"%s","filename":"%s","progress":%lu,"bytes_sent":%lu,"total_bytes":%lu,"customer_id":"%s"}
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30) >=60
 
}
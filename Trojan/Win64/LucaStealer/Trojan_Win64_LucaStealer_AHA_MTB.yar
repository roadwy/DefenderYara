
rule Trojan_Win64_LucaStealer_AHA_MTB{
	meta:
		description = "Trojan:Win64/LucaStealer.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 48 6f 6c 6c 6f 77 69 6e 67 20 66 61 69 6c 65 64 2c 20 72 75 6e 6e 69 6e 67 20 61 73 20 6e 6f 72 6d 61 6c 20 70 72 6f 63 65 73 73 2e } //30 @Hollowing failed, running as normal process.
		$a_01_1 = {40 52 65 76 65 72 73 65 20 50 72 6f 78 79 20 72 65 71 75 65 73 74 65 64 20 28 73 74 75 62 29 } //20 @Reverse Proxy requested (stub)
		$a_01_2 = {40 70 6b 67 65 74 64 69 73 63 6f 72 64 74 6f 6b 65 6e 73 } //10 @pkgetdiscordtokens
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}
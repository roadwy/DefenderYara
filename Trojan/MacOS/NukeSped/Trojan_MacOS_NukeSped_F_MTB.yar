
rule Trojan_MacOS_NukeSped_F_MTB{
	meta:
		description = "Trojan:MacOS/NukeSped.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 6b 75 70 61 79 77 61 6c 6c 65 74 2e 63 6f 6d 2f 6b 75 70 61 79 5f 75 70 64 61 74 65 2e 70 68 70 } //2 ://kupaywallet.com/kupay_update.php
		$a_00_1 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 6b 75 70 61 79 5f 75 70 64 61 74 65 } //1 /private/tmp/kupay_update
		$a_00_2 = {43 6f 69 6e 47 6f 5f 54 72 61 64 65 } //1 CoinGo_Trade
		$a_00_3 = {3a 2f 2f 32 33 2e 31 35 32 2e 30 2e 31 30 31 3a 38 30 38 30 } //2 ://23.152.0.101:8080
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2) >=3
 
}
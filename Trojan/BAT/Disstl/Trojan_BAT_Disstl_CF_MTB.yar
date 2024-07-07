
rule Trojan_BAT_Disstl_CF_MTB{
	meta:
		description = "Trojan:BAT/Disstl.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {64 6f 6e 74 20 73 68 61 72 65 20 74 68 69 73 20 73 74 65 61 6c 65 72 20 61 6e 79 77 68 65 72 65 } //1 dont share this stealer anywhere
		$a_81_1 = {64 63 64 2e 65 78 65 } //1 dcd.exe
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 65 74 65 72 6e 69 74 79 70 72 2e 6e 65 74 } //1 https://eternitypr.net
		$a_81_3 = {47 72 6f 77 74 6f 70 69 61 5c 73 61 76 65 2e 64 61 74 } //1 Growtopia\save.dat
		$a_81_4 = {77 65 62 68 6f 6f 6b 75 72 6c } //1 webhookurl
		$a_81_5 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_81_6 = {53 65 6e 64 69 6e 67 20 69 6e 66 6f 20 74 6f 20 45 74 65 72 6e 69 74 79 } //1 Sending info to Eternity
		$a_81_7 = {67 72 6f 77 74 6f 70 69 61 31 2e 63 6f 6d } //1 growtopia1.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
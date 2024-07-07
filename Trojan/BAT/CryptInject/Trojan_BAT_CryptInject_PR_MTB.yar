
rule Trojan_BAT_CryptInject_PR_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 35 30 34 31 66 63 31 65 2d 33 31 65 64 2d 34 39 39 64 2d 62 66 38 39 2d 62 33 66 63 31 31 34 32 63 30 66 37 } //1 $5041fc1e-31ed-499d-bf89-b3fc1142c0f7
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 63 6f 69 6e 6d 61 72 6b 65 74 63 61 70 2e 63 6f 6d 2f 76 31 2f 74 69 63 6b 65 72 2f } //1 https://api.coinmarketcap.com/v1/ticker/
		$a_81_2 = {53 69 6d 70 6c 65 54 69 63 6b 65 72 } //1 SimpleTicker
		$a_81_3 = {48 65 6c 6c 6f 21 20 54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 74 72 79 69 6e 67 20 6f 75 74 20 57 46 47 21 } //1 Hello! Thank you for trying out WFG!
		$a_81_4 = {53 69 6d 70 6c 65 54 69 63 6b 65 72 57 69 6e 64 6f 77 73 46 6f 72 6d 73 2e 53 69 6d 70 6c 65 54 69 63 6b 65 72 56 69 65 77 2e 72 65 73 6f 75 72 63 65 73 } //1 SimpleTickerWindowsForms.SimpleTickerView.resources
		$a_81_5 = {6c 62 6c 54 69 63 6b 65 72 46 6f 72 6d 61 74 49 6e 73 74 72 75 63 74 69 6f 6e 73 2e 54 65 78 74 } //1 lblTickerFormatInstructions.Text
		$a_81_6 = {41 20 73 69 6d 70 6c 65 20 74 69 63 6b 65 72 20 74 6f 20 64 69 73 70 6c 61 79 20 76 61 72 69 6f 75 73 20 63 72 79 70 74 6f 63 75 72 72 65 6e 63 79 20 70 72 69 63 65 73 } //1 A simple ticker to display various cryptocurrency prices
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
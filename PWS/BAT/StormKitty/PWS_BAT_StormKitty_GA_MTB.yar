
rule PWS_BAT_StormKitty_GA_MTB{
	meta:
		description = "PWS:BAT/StormKitty.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0b 00 00 "
		
	strings :
		$a_80_0 = {2f 4c 69 6d 65 72 42 6f 79 2f 53 74 6f 72 6d 4b 69 74 74 79 } ///LimerBoy/StormKitty  10
		$a_80_1 = {2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 3f 63 68 61 74 5f 69 64 3d } ///sendDocument?chat_id=  1
		$a_80_2 = {40 4d 61 64 43 6f 64 } //@MadCod  1
		$a_80_3 = {43 72 65 64 69 74 43 61 72 64 } //CreditCard  1
		$a_80_4 = {57 61 6c 6c 65 74 } //Wallet  1
		$a_80_5 = {54 65 6c 65 67 72 61 6d } //Telegram  1
		$a_80_6 = {47 72 61 62 62 65 72 } //Grabber  1
		$a_80_7 = {50 61 79 70 61 6c } //Paypal  1
		$a_80_8 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  1
		$a_80_9 = {43 61 6d 65 72 61 } //Camera  1
		$a_80_10 = {4d 65 67 61 44 75 6d 70 65 72 } //MegaDumper  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=16
 
}

rule Trojan_Win64_SeidrStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/SeidrStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {2f 6f 75 74 70 75 74 2f 77 61 6c 6c 65 74 73 2f 65 6c 65 63 74 72 75 6d } ///output/wallets/electrum  10
		$a_80_1 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //api.telegram.org/bot  10
		$a_80_2 = {77 65 62 64 61 74 61 } //webdata  1
		$a_80_3 = {63 6f 6f 6b 69 65 } //cookie  1
		$a_80_4 = {73 65 73 73 69 6f 6e } //session  1
		$a_80_5 = {61 75 74 6f 66 69 6c 6c } //autofill  1
		$a_80_6 = {6c 6f 67 69 6e 64 61 74 61 } //logindata  1
		$a_80_7 = {43 61 72 64 20 4e 75 6d 62 65 72 3a } //Card Number:  1
		$a_80_8 = {50 61 73 73 77 6f 72 64 3a } //Password:  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=27
 
}

rule Trojan_BAT_ClipBanker_XS_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.XS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {62 69 74 63 6f 69 6e 6d 69 6e 69 6e 67 73 6f 66 74 77 61 72 65 2e 42 69 74 63 6f 69 6e 5f 47 72 61 62 62 65 72 } //1 bitcoinminingsoftware.Bitcoin_Grabber
		$a_81_1 = {43 6c 69 70 62 6f 61 72 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 ClipboardNotification
		$a_81_2 = {62 69 74 63 6f 69 6e 6d 69 6e 69 6e 67 73 6f 66 74 77 61 72 65 2e 70 64 62 } //1 bitcoinminingsoftware.pdb
		$a_81_3 = {79 6f 75 72 5f 42 74 63 } //1 your_Btc
		$a_81_4 = {24 33 31 66 36 32 33 33 34 2d 65 64 65 63 2d 34 66 63 66 2d 62 32 35 38 2d 33 65 63 61 66 32 61 35 35 33 39 65 } //1 $31f62334-edec-4fcf-b258-3ecaf2a5539e
		$a_81_5 = {30 30 34 46 45 43 32 34 2d 33 35 44 34 2d 34 42 45 31 2d 41 33 38 39 2d 33 31 41 38 35 31 31 38 46 42 43 34 } //1 004FEC24-35D4-4BE1-A389-31A85118FBC4
		$a_81_6 = {63 68 34 58 47 37 72 72 35 59 48 61 50 4a 42 47 4b 70 } //1 ch4XG7rr5YHaPJBGKp
		$a_81_7 = {47 57 38 55 64 74 64 74 46 64 63 72 77 4b 38 75 72 5a } //1 GW8UdtdtFdcrwK8urZ
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
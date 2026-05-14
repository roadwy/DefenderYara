
rule Trojan_Win64_SkuldStealer_MX_MTB{
	meta:
		description = "Trojan:Win64/SkuldStealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 61 63 6b 69 72 62 79 2f 73 6b 75 6c 64 } //1 hackirby/skuld
		$a_01_1 = {43 68 72 6f 6d 69 75 6d 53 74 65 61 6c } //1 ChromiumSteal
		$a_01_2 = {62 72 6f 77 73 65 72 73 2e 47 65 63 6b 6f 53 74 65 61 6c } //1 browsers.GeckoSteal
		$a_01_3 = {62 72 6f 77 73 65 72 73 2e 28 2a 43 68 72 6f 6d 69 75 6d 29 2e 47 65 74 43 72 65 64 69 74 43 61 72 64 73 } //1 browsers.(*Chromium).GetCreditCards
		$a_01_4 = {62 72 6f 77 73 65 72 73 2e 48 69 73 74 6f 72 79 } //1 browsers.History
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
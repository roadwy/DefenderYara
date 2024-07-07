
rule Trojan_Win64_GOStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/GOStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {4e 65 77 53 74 65 61 6c 65 72 } //1 NewStealer
		$a_01_2 = {73 63 72 65 65 6e 73 68 6f 74 } //1 screenshot
		$a_01_3 = {47 72 61 62 53 63 72 65 65 6e } //1 GrabScreen
		$a_01_4 = {77 61 6c 6c 65 74 } //1 wallet
		$a_01_5 = {64 69 73 63 6f 72 64 } //1 discord
		$a_01_6 = {62 72 6f 77 73 65 72 } //1 browser
		$a_01_7 = {62 6f 74 6e 65 74 } //1 botnet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
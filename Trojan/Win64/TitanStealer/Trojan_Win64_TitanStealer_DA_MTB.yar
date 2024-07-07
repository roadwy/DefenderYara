
rule Trojan_Win64_TitanStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/TitanStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {73 74 65 61 6c 65 72 5f 76 } //1 stealer_v
		$a_01_2 = {73 63 72 65 65 6e 73 68 6f 74 2e 43 61 70 74 75 72 65 53 63 72 65 65 6e } //1 screenshot.CaptureScreen
		$a_01_3 = {43 68 72 6f 6d 65 43 6f 6d 6d 6f 6e 43 6f 6f 6b 69 65 } //1 ChromeCommonCookie
		$a_01_4 = {67 72 61 62 66 69 6c 65 } //1 grabfile
		$a_01_5 = {61 6e 74 69 64 65 62 75 67 } //1 antidebug
		$a_01_6 = {61 6e 74 69 76 6d } //1 antivm
		$a_01_7 = {74 69 6d 65 2e 53 6c 65 65 70 } //1 time.Sleep
		$a_01_8 = {6d 61 73 74 65 72 20 73 65 63 72 65 74 } //1 master secret
		$a_01_9 = {73 65 6e 64 6c 6f 67 } //1 sendlog
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
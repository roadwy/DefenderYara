
rule Trojan_Win32_LummaStealer_CCEX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {80 2c 3e 6a 6a } //1
		$a_01_1 = {80 34 3e 8b 6a } //1
		$a_01_2 = {80 34 3e 85 6a } //1
		$a_01_3 = {80 04 3e b1 6a } //1
		$a_01_4 = {80 34 3e f1 6a } //1
		$a_01_5 = {80 04 3e 4b 6a } //1
		$a_01_6 = {80 04 3e ad 6a } //1
		$a_01_7 = {80 34 3e a8 6a } //1
		$a_01_8 = {80 04 3e f8 6a } //1
		$a_03_9 = {80 04 3e 6f 46 3b 74 24 ?? 0f 82 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*1) >=10
 
}
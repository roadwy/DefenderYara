
rule Trojan_BAT_RedLineStealer_AX_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {72 2f 00 00 70 28 0a ?? ?? 06 1d 3a 43 ?? ?? 00 26 20 00 ?? ?? 00 7e 33 ?? ?? 04 7b 44 ?? ?? 04 39 c9 ?? ?? ff 26 20 00 ?? 00 00 } //1
		$a_03_1 = {69 18 3a 17 ?? ?? 00 26 26 26 38 0a ?? ?? 00 38 e7 ?? ?? ff 38 e2 ?? ?? ff 38 dd ?? ?? ff 28 35 ?? ?? 0a 38 e7 ?? ?? ff 90 0a 2c 00 02 16 02 8e } //1
		$a_01_2 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 HttpWebResponse
		$a_01_3 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {50 75 73 68 56 61 6c } //1 PushVal
		$a_81_6 = {33 37 2e 30 2e 31 31 2e 31 36 34 } //1 37.0.11.164
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
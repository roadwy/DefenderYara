
rule Backdoor_BAT_Bladabindi_BM{
	meta:
		description = "Backdoor:BAT/Bladabindi.BM,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7c 00 35 00 32 00 33 00 7c 00 } //1 |523|
		$a_01_1 = {5b 00 65 00 6e 00 64 00 6f 00 66 00 5d 00 } //1 [endof]
		$a_01_2 = {66 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 2d 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 72 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 6d 00 65 00 2e 00 6e 00 65 00 74 00 } //1 facebook-profile.redirectme.net
		$a_01_3 = {53 00 65 00 61 00 72 00 63 00 68 00 55 00 69 00 2e 00 65 00 78 00 65 00 } //1 SearchUi.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
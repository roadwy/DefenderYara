
rule Trojan_BAT_PureLogStealer_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer!MTB,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 05 00 00 "
		
	strings :
		$a_80_0 = {24 36 31 37 34 31 64 39 31 2d 65 35 38 66 2d 34 62 63 35 2d 62 66 31 32 2d 38 33 65 33 65 61 37 62 30 61 35 33 } //$61741d91-e58f-4bc5-bf12-83e3ea7b0a53  50
		$a_80_1 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d } //{11111-22222-  1
		$a_80_2 = {42 61 73 65 36 34 53 74 72 69 6e 67 } //Base64String  1
		$a_80_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //DebuggingModes  1
		$a_80_4 = {47 65 74 42 79 74 65 73 } //GetBytes  1
	condition:
		((#a_80_0  & 1)*50+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=52
 
}
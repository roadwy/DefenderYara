
rule Trojan_BAT_LummaStealer_DF_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 77 61 73 61 6b 6a 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Dwasakj.Properties.Resources  20
		$a_80_1 = {67 65 74 5f 43 6f 6f 6b 69 65 43 6f 6e 74 61 69 6e 65 72 } //get_CookieContainer  1
		$a_80_2 = {67 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //get_Credentials  1
		$a_80_3 = {47 65 74 42 79 74 65 73 } //GetBytes  1
		$a_80_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
		$a_80_5 = {42 61 73 65 36 34 53 74 72 69 6e 67 } //Base64String  1
		$a_80_6 = {66 69 6c 65 3a 2f 2f 2f } //file:///  1
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=26
 
}
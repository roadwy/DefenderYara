
rule Backdoor_BAT_Bladabindi_KS_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 18 18 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 ?? 11 ?? 14 72 90 0a 24 00 28 ?? ?? ?? 0a 02 11 } //1
		$a_01_1 = {43 69 70 68 65 72 4d 6f 64 65 } //1 CipherMode
		$a_01_2 = {50 61 64 64 69 6e 67 4d 6f 64 65 } //1 PaddingMode
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
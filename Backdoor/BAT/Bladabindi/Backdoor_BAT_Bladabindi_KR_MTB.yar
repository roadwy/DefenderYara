
rule Backdoor_BAT_Bladabindi_KR_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 0d 06 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 90 0a 2b 00 02 08 28 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_3 = {43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 CurrentDomain
		$a_01_4 = {45 6e 74 72 79 50 6f 69 6e 74 } //1 EntryPoint
		$a_01_5 = {43 6f 6e 76 65 72 73 69 6f 6e 73 } //1 Conversions
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
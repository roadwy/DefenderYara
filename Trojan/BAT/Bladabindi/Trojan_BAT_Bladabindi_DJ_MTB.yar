
rule Trojan_BAT_Bladabindi_DJ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 06 11 ?? 17 28 ?? ?? ?? 0a a2 25 18 07 11 ?? 17 28 ?? ?? ?? 0a a2 25 19 08 11 ?? 17 28 ?? ?? ?? 0a a2 25 1a 09 11 ?? 17 28 ?? ?? ?? 0a a2 25 1b 11 04 11 ?? 17 28 ?? ?? ?? 0a 90 09 0b 00 1f ?? 8d ?? ?? ?? 01 25 16 11 } //10
		$a_81_1 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}
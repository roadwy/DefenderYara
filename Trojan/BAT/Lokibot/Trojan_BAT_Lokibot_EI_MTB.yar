
rule Trojan_BAT_Lokibot_EI_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {51 33 4a 35 63 48 52 6c 5a 43 42 6d 5a 69 51 3d } //1 Q3J5cHRlZCBmZiQ=
		$a_81_1 = {43 72 79 70 74 65 64 20 66 66 } //1 Crypted ff
		$a_81_2 = {5f 45 6e 63 72 79 70 74 65 64 24 } //1 _Encrypted$
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_81_6 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_7 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
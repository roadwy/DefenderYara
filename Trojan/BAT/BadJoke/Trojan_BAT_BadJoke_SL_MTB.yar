
rule Trojan_BAT_BadJoke_SL_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 36 38 35 62 38 30 64 37 2d 63 34 64 35 2d 34 35 64 32 2d 61 61 33 66 2d 35 34 32 63 65 35 34 62 62 37 38 30 } //1 $685b80d7-c4d5-45d2-aa3f-542ce54bb780
		$a_81_1 = {57 72 61 69 74 68 41 43 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 WraithAC.Properties.Resources
		$a_81_2 = {66 75 63 6b 20 79 6f 75 } //1 fuck you
		$a_81_3 = {2e 63 6f 6d 70 72 65 73 73 65 64 } //1 .compressed
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
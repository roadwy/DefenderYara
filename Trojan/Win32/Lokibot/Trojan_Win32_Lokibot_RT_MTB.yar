
rule Trojan_Win32_Lokibot_RT_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {61 68 61 74 79 } //1 ahaty
		$a_81_1 = {62 70 75 7a 70 6c 6f 7a 6a } //1 bpuzplozj
		$a_81_2 = {63 63 72 69 } //1 ccri
		$a_81_3 = {68 77 68 6f 79 64 } //1 hwhoyd
		$a_81_4 = {70 74 68 66 68 74 63 71 68 } //1 pthfhtcqh
		$a_81_5 = {73 77 6f 68 64 6c 75 79 79 69 68 } //1 swohdluyyih
		$a_81_6 = {76 72 70 76 77 76 64 79 } //1 vrpvwvdy
		$a_81_7 = {77 75 64 6d 76 } //1 wudmv
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
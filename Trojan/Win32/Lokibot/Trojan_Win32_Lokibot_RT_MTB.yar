
rule Trojan_Win32_Lokibot_RT_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 68 61 74 79 } //01 00  ahaty
		$a_81_1 = {62 70 75 7a 70 6c 6f 7a 6a } //01 00  bpuzplozj
		$a_81_2 = {63 63 72 69 } //01 00  ccri
		$a_81_3 = {68 77 68 6f 79 64 } //01 00  hwhoyd
		$a_81_4 = {70 74 68 66 68 74 63 71 68 } //01 00  pthfhtcqh
		$a_81_5 = {73 77 6f 68 64 6c 75 79 79 69 68 } //01 00  swohdluyyih
		$a_81_6 = {76 72 70 76 77 76 64 79 } //01 00  vrpvwvdy
		$a_81_7 = {77 75 64 6d 76 } //00 00  wudmv
	condition:
		any of ($a_*)
 
}
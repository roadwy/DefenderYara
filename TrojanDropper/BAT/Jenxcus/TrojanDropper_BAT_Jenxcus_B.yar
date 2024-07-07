
rule TrojanDropper_BAT_Jenxcus_B{
	meta:
		description = "TrojanDropper:BAT/Jenxcus.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 27 3c 5b 20 63 6f 64 65 64 20 62 59 20 6e 6a 71 38 20 5d 3e 27 } //1 ('<[ coded bY njq8 ]>'
		$a_01_1 = {56 00 42 00 53 00 7c 00 2a 00 2e 00 56 00 62 00 73 00 } //1 VBS|*.Vbs
		$a_01_2 = {42 75 69 6c 64 69 6e 67 20 57 6f 72 6d 20 4e 6a } //1 Building Worm Nj
		$a_01_3 = {6e 6a 5f 77 6f 72 6d } //1 nj_worm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
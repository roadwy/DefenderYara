
rule Trojan_BAT_AgentTesla_RSL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 9f b6 3f 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 76 00 00 00 19 00 00 00 6c 00 00 00 fa 00 00 00 2e 00 00 00 05 00 00 00 c0 00 00 00 01 00 00 00 48 00 00 00 01 00 00 00 26 00 00 00 01 00 00 00 01 00 00 00 04 00 00 00 0b 00 00 00 15 00 00 00 08 00 00 00 01 00 00 00 10 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 03 00 00 00 0f 00 00 00 05 00 00 00 13 } //1
		$a_81_1 = {33 63 31 37 61 64 63 62 2d 31 32 34 61 2d 34 64 38 66 2d 62 62 38 64 2d 37 66 34 36 33 39 61 34 35 64 64 65 } //1 3c17adcb-124a-4d8f-bb8d-7f4639a45dde
		$a_81_2 = {4d 6f 76 65 42 65 74 77 65 65 6e 4c 69 73 74 42 6f 78 65 73 } //1 MoveBetweenListBoxes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
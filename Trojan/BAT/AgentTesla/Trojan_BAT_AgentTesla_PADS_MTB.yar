
rule Trojan_BAT_AgentTesla_PADS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 6f 00 75 00 6e 00 64 00 5c 00 6d 00 61 00 79 00 66 00 61 00 6c 00 6c 00 2e 00 57 00 41 00 56 00 } //01 00  ..\..\sound\mayfall.WAV
		$a_01_1 = {2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 6f 00 75 00 6e 00 64 00 5c 00 6b 00 69 00 6c 00 6c 00 2e 00 57 00 41 00 56 00 } //01 00  ..\..\sound\kill.WAV
		$a_01_2 = {2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 6f 00 75 00 6e 00 64 00 5c 00 62 00 6b 00 5f 00 6d 00 75 00 73 00 69 00 63 00 5c 00 66 00 69 00 72 00 73 00 74 00 2e 00 57 00 41 00 56 00 } //01 00  ..\..\sound\bk_music\first.WAV
		$a_01_3 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3f 00 72 00 65 00 73 00 69 00 64 00 3d 00 } //01 00  /download?resid=
		$a_01_4 = {2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 63 00 75 00 72 00 73 00 6f 00 72 00 5c 00 68 00 61 00 72 00 72 00 6f 00 77 00 2e 00 63 00 75 00 72 00 } //00 00  ..\..\cursor\harrow.cur
	condition:
		any of ($a_*)
 
}
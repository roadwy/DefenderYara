
rule Trojan_BAT_AgentTesla_JHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 07 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? 0a 00 00 00 09 16 fe 02 13 05 11 05 2d d0 08 6f } //10
		$a_03_1 = {08 09 9a 13 04 00 11 04 28 ?? ?? ?? 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 28 ?? ?? ?? 0a 69 13 05 06 11 05 d1 6f ?? ?? ?? 0a 26 00 09 17 58 0d 09 08 8e 69 32 cc } //10
		$a_81_2 = {33 38 32 20 34 32 36 20 34 32 33 20 34 32 31 20 33 37 38 20 34 30 39 20 34 32 37 20 34 31 33 20 33 36 36 20 33 36 34 20 33 39 35 20 34 32 38 20 34 32 36 20 34 31 37 20 34 32 32 20 34 31 35 } //1 382 426 423 421 378 409 427 413 366 364 395 428 426 417 422 415
		$a_81_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=22
 
}
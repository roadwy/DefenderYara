
rule Trojan_BAT_AgentTesla_MBU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {34 44 2d 35 41 2d 39 4f 2d 4f 4f 2d 4f 33 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 34 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 46 46 2d 46 46 2d 4f 4f 2d 4f 4f 2d 42 38 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 34 4f } //01 00  4D-5A-9O-OO-O3-OO-OO-OO-O4-OO-OO-OO-FF-FF-OO-OO-B8-OO-OO-OO-OO-OO-OO-OO-4O
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //01 00  System.Convert
		$a_01_2 = {53 70 6c 69 74 } //01 00  Split
		$a_01_3 = {54 00 6f 00 42 00 79 00 74 00 65 00 } //01 00  ToByte
		$a_01_4 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}